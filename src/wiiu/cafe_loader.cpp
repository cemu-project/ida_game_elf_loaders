#include "cafe_loader.h"
#include "cafe.h"
#include "tinfl.c"

#include <algorithm>
#include <cstring>
#include <map>
#include <utility>

constexpr uint32 kImportHeaderSize = 8;
constexpr uint32 kRplFlagIsRpx = 1u << 1;
constexpr ea_t kImportThunkSize = 8;
constexpr ea_t kRel24TrampolineSize = 16;

constexpr uint32 R_PPC_GHS_REL16_HA = 251;
constexpr uint32 R_PPC_GHS_REL16_HI = 252;
constexpr uint32 R_PPC_GHS_REL16_LO = 253;

template <typename T>
T read_be(const T &value)
{
  T tmp = value;
  swap(tmp);
  return tmp;
}

static ea_t align_up_ea(ea_t value, ea_t align)
{
  if (align <= 1)
    return value;
  return (value + align - 1) & ~(align - 1);
}

static ea_t align_down_ea(ea_t value, ea_t align)
{
  if (align <= 1)
    return value;
  return value & ~(align - 1);
}

static bool starts_with(const char *text, const char *prefix)
{
  return text != nullptr && prefix != nullptr
      && std::strncmp(text, prefix, std::strlen(prefix)) == 0;
}

static qstring make_import_label(const std::string &module_name,
                                 const std::string &symbol_name)
{
  qstring label(symbol_name.c_str());
  if (validate_name(&label, VNT_IDENT, SN_NOCHECK))
    return label;

  label = module_name.c_str();
  label += "__";
  label += symbol_name.c_str();
  validate_name(&label, VNT_IDENT, SN_NOCHECK);

  if (label.empty())
    label = "import_symbol";

  return label;
}

static bool calc_rel24(uint32 *out, ea_t value, ea_t from)
{
  const int32 distance = static_cast<int32>(value) - static_cast<int32>(from);
  if ((distance & 3) != 0)
    return false;
  if (distance > 0x1FFFFFC || distance < -0x2000000)
    return false;
  *out = static_cast<uint32>(distance) & 0x03FFFFFC;
  return true;
}

static bool calc_rel14(uint16 *out, ea_t value, ea_t from)
{
  const int32 distance = static_cast<int32>(value) - static_cast<int32>(from);
  if ((distance & 3) != 0)
    return false;
  if (distance > 0x7FFC || distance < -0x8000)
    return false;
  *out = static_cast<uint16>(distance) & 0xFFFC;
  return true;
}

static ea_t decode_branch_target(uint32 inst, ea_t from)
{
  int32 distance = static_cast<int32>(inst & 0x03FFFFFC);
  if ((distance & 0x02000000) != 0)
    distance |= static_cast<int32>(0xFC000000);

  if ((inst & 2) != 0)
    return static_cast<ea_t>(distance);

  return static_cast<ea_t>(static_cast<int32>(from) + distance);
}

cafe_loader::cafe_loader(elf_reader<elf32> *elf)
  : m_elf(elf),
    m_sdaBase(0),
    m_sda2Base(0),
    m_textSize(0),
    m_trampAdjust(0),
    m_tlsModuleIndex(-1),
    m_haveFileInfo(false),
    m_haveTextRegion(false),
    m_isRpx(false),
    m_textAllocBase(BADADDR),
    m_textAllocEnd(BADADDR),
    m_textLoadStart(BADADDR),
    m_textLoadEnd(BADADDR),
    m_importThunkStart(BADADDR),
    m_importThunkEnd(BADADDR),
    m_preTrampStart(BADADDR),
    m_preTrampCursor(BADADDR),
    m_postTrampCursor(BADADDR),
    m_postTrampEnd(BADADDR)
{
}

void cafe_loader::apply()
{
  applySegments();
  swapSymbols();
  collectFileInfo();
  collectImports();
  collectImportThunks();
  createTextTrampolineSegments();
  applyRelocations();
  processImports();
  processExports();
  applySymbols();
}

void cafe_loader::applySegments()
{
  auto &sections = m_elf->getSections();

  // Decompress sections before loading them into the database.
  for (auto &section : sections)
  {
    if ((section.sh_flags & ELF_SECTIONFLAGEX_CAFE_RPL_COMPZ) == 0)
      continue;

    const char *data = section.data();
    if (data == nullptr || section.sh_size < sizeof(uint32))
      continue;

    uint32 deflated_len = 0;
    std::memcpy(&deflated_len, data, sizeof(deflated_len));
    swap(deflated_len);

    auto *deflated_data = new unsigned char[deflated_len];
    deflated_len = tinfl_decompress_mem_to_mem(
      deflated_data,
      deflated_len,
      data + sizeof(uint32),
      section.sh_size - sizeof(uint32),
      TINFL_FLAG_PARSE_ZLIB_HEADER);

    if (deflated_len == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED)
    {
      msg("Failed to decompress section at %08X\n", section.sh_addr);
      delete[] deflated_data;
      continue;
    }

    section.setData(reinterpret_cast<const char *>(deflated_data), deflated_len);
    delete[] deflated_data;
  }

  const char *string_table = m_elf->getSectionStringTable() != nullptr
                           ? m_elf->getSectionStringTable()->data()
                           : nullptr;

  size_t index = 0;
  for (auto &section : sections)
  {
    if ((section.sh_flags & SHF_ALLOC) == 0)
      continue;
    if (section.sh_type == SHT_NULL)
      continue;

    uchar perm = SEGPERM_READ;
    const char *sclass = CLASS_DATA;

    if ((section.sh_flags & SHF_WRITE) != 0)
      perm |= SEGPERM_WRITE;
    if ((section.sh_flags & SHF_EXECINSTR) != 0)
      perm |= SEGPERM_EXEC;

    if ((section.sh_flags & SHF_EXECINSTR) != 0
        && section.sh_type != ELF_SECTIONTYPE_CAFE_RPL_IMPORTS
        && section.sh_type != ELF_SECTIONTYPE_CAFE_RPL_EXPORTS)
    {
      sclass = CLASS_CODE;
    }
    else if (section.sh_type == SHT_NOBITS)
    {
      sclass = CLASS_BSS;
    }

    const char *name = "";
    if (string_table != nullptr && section.sh_name != 0)
      name = &string_table[section.sh_name];

    const bool load = section.sh_type != SHT_NOBITS;
    const char *section_data = nullptr;
    uint32 section_size = section.sh_size;
    if (load)
    {
      section_data = section.data();
      section_size = section.getSize();
    }

    applySegment(static_cast<uint32>(index),
                 section_data,
                 section.sh_addr,
                 section_size,
                 name,
                 sclass,
                 perm,
                 m_elf->getAlignment(section.sh_addralign),
                 load);
    ++index;
  }
}

void cafe_loader::applySegment(uint32 sel,
                               const char *data,
                               uint32 addr,
                               uint32 size,
                               const char *name,
                               const char *sclass,
                               uchar perm,
                               uchar align,
                               bool load)
{
  set_selector(sel, 0);

  segment_info_t si;
  si.start_ea = addr;
  si.end_ea = addr + size;
  si.set_sel(sel);
  si.set_orgbase(sel);
  si.set_bitness(1); // 32-bit
  si.set_comb(scPub);
  si.set_perm(perm);
  si.set_flags(SFL_LOADER);
  si.set_align(align);
  si.set_name(name != nullptr ? name : "");
  si.set_sclass(sclass);

  add_segment_ex(&si, ADDSEG_NOSREG);

  if (load && data != nullptr && size != 0)
    mem2base(data, addr, addr + size, BADADDR);
}

void cafe_loader::collectFileInfo()
{
  m_haveFileInfo = false;
  m_sdaBase = 0;
  m_sda2Base = 0;
  m_textSize = 0;
  m_trampAdjust = 0;
  m_tlsModuleIndex = -1;
  m_isRpx = false;

  for (auto &section : m_elf->getSections())
  {
    if (section.sh_type != ELF_SECTIONTYPE_CAFE_RPL_FILEINFO)
      continue;

    const char *data = section.data();
    if (data == nullptr || section.getSize() < sizeof(uint32))
      return;

    uint32 version = 0;
    std::memcpy(&version, data, sizeof(version));
    swap(version);

    if (version >= 0xCAFE0402 && section.getSize() >= sizeof(CAFE_RPL_FILE_INFO_4_2))
    {
      const auto *info = reinterpret_cast<const CAFE_RPL_FILE_INFO_4_2 *>(data);
      m_textSize = read_be(info->mRegBytes_Text);
      m_trampAdjust = read_be(info->mTrampAdj);
      m_sdaBase = read_be(info->mSDABase);
      m_sda2Base = read_be(info->mSDA2Base);
      m_tlsModuleIndex = static_cast<int16>(read_be(info->mTLSModuleIndex));
      m_isRpx = (read_be(info->mFlags) & kRplFlagIsRpx) != 0;
      m_haveFileInfo = true;
      return;
    }

    if (version >= 0xCAFE0401 && section.getSize() >= sizeof(CAFE_RPL_FILE_INFO_4_1))
    {
      const auto *info = reinterpret_cast<const CAFE_RPL_FILE_INFO_4_1 *>(data);
      m_textSize = read_be(info->mRegBytes_Text);
      m_trampAdjust = read_be(info->mTrampAdj);
      m_sdaBase = read_be(info->mSDABase);
      m_sda2Base = read_be(info->mSDA2Base);
      m_isRpx = (read_be(info->mFlags) & kRplFlagIsRpx) != 0;
      m_haveFileInfo = true;
      return;
    }

    if (section.getSize() >= sizeof(CAFE_RPL_FILE_INFO_3_0))
    {
      const auto *info = reinterpret_cast<const CAFE_RPL_FILE_INFO_3_0 *>(data);
      m_textSize = read_be(info->mRegBytes_Text);
      m_trampAdjust = read_be(info->mTrampAdj);
      m_sdaBase = read_be(info->mSDABase);
      m_sda2Base = read_be(info->mSDA2Base);
      m_haveFileInfo = true;
      return;
    }

    return;
  }
}

void cafe_loader::createTextTrampolineSegments()
{
  m_haveTextRegion = false;
  m_textAllocBase = BADADDR;
  m_textAllocEnd = BADADDR;
  m_textLoadStart = BADADDR;
  m_textLoadEnd = BADADDR;
  m_preTrampStart = BADADDR;
  m_preTrampCursor = BADADDR;
  m_postTrampCursor = BADADDR;
  m_postTrampEnd = BADADDR;
  m_internalTrampolines.clear();

  if (!m_haveFileInfo || m_textSize == 0)
    return;

  for (const auto &section : m_elf->getSections())
  {
    if ((section.sh_flags & SHF_ALLOC) == 0 || (section.sh_flags & SHF_EXECINSTR) == 0)
      continue;
    if (section.sh_type == ELF_SECTIONTYPE_CAFE_RPL_IMPORTS
        || section.sh_type == ELF_SECTIONTYPE_CAFE_RPL_EXPORTS
        || section.getSize() == 0)
    {
      continue;
    }

    m_textLoadStart = m_textLoadStart == BADADDR
                    ? static_cast<ea_t>(section.sh_addr)
                    : std::min(m_textLoadStart, static_cast<ea_t>(section.sh_addr));
    m_textLoadEnd = m_textLoadEnd == BADADDR
                  ? static_cast<ea_t>(section.sh_addr + section.getSize())
                  : std::max(m_textLoadEnd, static_cast<ea_t>(section.sh_addr + section.getSize()));
  }

  if (m_textLoadStart == BADADDR || m_textLoadEnd == BADADDR || m_textLoadStart < m_trampAdjust)
    return;

  m_textAllocBase = m_textLoadStart - m_trampAdjust;
  m_textAllocEnd = m_textAllocBase + m_textSize;
  m_haveTextRegion = m_textAllocEnd > m_textLoadStart;
  if (!m_haveTextRegion || m_textAllocEnd <= m_textLoadEnd)
    return;

  uint32 next_sel = m_elf->getNumSections();
  const ea_t pre_tramp_end = align_down_ea(m_textLoadStart, kRel24TrampolineSize);
  if (m_textAllocBase < pre_tramp_end)
  {
    m_preTrampStart = m_textAllocBase;
    m_preTrampCursor = pre_tramp_end;
    applySegment(next_sel++,
                 nullptr,
                 static_cast<uint32>(m_textAllocBase),
                 static_cast<uint32>(pre_tramp_end - m_textAllocBase),
                 ".tramp_pre",
                 CLASS_CODE,
                 SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC,
                 saRelQword,
                 false);
  }

  if (m_textLoadEnd < m_textAllocEnd)
  {
    const bool have_import_thunks =
      m_importThunkStart != BADADDR
      && m_importThunkEnd != BADADDR
      && m_importThunkStart >= m_textLoadEnd
      && m_importThunkStart < m_importThunkEnd
      && m_importThunkEnd <= m_textAllocEnd;

    if (have_import_thunks && m_textLoadEnd < m_importThunkStart)
    {
      applySegment(next_sel++,
                   nullptr,
                   static_cast<uint32>(m_textLoadEnd),
                   static_cast<uint32>(m_importThunkStart - m_textLoadEnd),
                   ".tramp_post",
                   CLASS_CODE,
                   SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC,
                   saRelQword,
                   false);
    }

    if (have_import_thunks)
    {
      applySegment(next_sel++,
                   nullptr,
                   static_cast<uint32>(m_importThunkStart),
                   static_cast<uint32>(m_importThunkEnd - m_importThunkStart),
                   ".extern",
                   "XTRN",
                   SEGPERM_READ | SEGPERM_EXEC,
                   saRelQword,
                   false);
    }

    const ea_t post_tramp_start = align_up_ea(
      have_import_thunks ? m_importThunkEnd : m_textLoadEnd,
      kRel24TrampolineSize);
    if (post_tramp_start < m_textAllocEnd)
    {
      m_postTrampCursor = post_tramp_start;
      m_postTrampEnd = m_textAllocEnd;
      applySegment(next_sel,
                   nullptr,
                   static_cast<uint32>(post_tramp_start),
                   static_cast<uint32>(m_textAllocEnd - post_tramp_start),
                   have_import_thunks ? ".tramp_tail" : ".tramp_post",
                   CLASS_CODE,
                   SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC,
                   saRelQword,
                   false);
    }
  }
}

bool cafe_loader::isImportSection(uint16 section_index) const
{
  if (section_index >= m_elf->getNumSections())
    return false;
  return m_elf->getSections()[section_index].sh_type == ELF_SECTIONTYPE_CAFE_RPL_IMPORTS;
}

void cafe_loader::collectImports()
{
  m_imports.clear();
  m_internalTrampolines.clear();

  auto *symbol_section = m_elf->getSymbolsSection();
  if (symbol_section == nullptr)
    return;

  const char *section_names = m_elf->getSectionStringTable() != nullptr
                            ? m_elf->getSectionStringTable()->data()
                            : nullptr;
  if (section_names == nullptr)
    return;

  auto nsym = symbol_section->getSize() / symbol_section->sh_entsize;
  auto *symbols = m_elf->getSymbols();
  const char *symbol_names = m_elf->getSections()[symbol_section->sh_link].data();

  m_symbol_imports.assign(nsym, -1);

  std::map<std::string, int> dedup;
  std::map<std::string, int32> tls_modules;
  int32 next_tls_module_index = m_tlsModuleIndex >= 0 ? m_tlsModuleIndex + 1 : 1;
  for (size_t i = 1; i < nsym; ++i)
  {
    const auto &symbol = symbols[i];
    if (!isImportSection(symbol.st_shndx) || symbol.st_name == 0)
      continue;

    const auto &import_section = m_elf->getSections()[symbol.st_shndx];
    if (symbol.st_value < import_section.sh_addr + kImportHeaderSize)
      continue;

    const char *section_name = &section_names[import_section.sh_name];
    const char *module_name = section_name;
    if (starts_with(section_name, ".fimport_") || starts_with(section_name, ".dimport_"))
      module_name = section_name + 9;

    const char *symbol_name = &symbol_names[symbol.st_name];
    if (symbol_name[0] == '\0')
      continue;

    const bool is_tls = ELF32_ST_TYPE(symbol.st_info) == STT_TLS;
    const bool is_function = starts_with(section_name, ".fimport_")
                          || ((import_section.sh_flags & SHF_EXECINSTR) != 0);
    const std::string key = std::string(module_name) + '\n' + symbol_name
                          + (is_tls ? '\x02' : '\x03')
                          + (is_function ? '\x01' : '\x00');

    auto it = dedup.find(key);
    if (it != dedup.end())
    {
      m_symbol_imports[i] = it->second;
      continue;
    }

    import imp;
    imp.symbol_index = static_cast<uint32>(i);
    imp.table_ea = symbol.st_value;
    imp.thunk_ea = BADADDR;
    imp.module = module_name;
    imp.name = symbol_name;
    imp.tls_module_index = -1;
    imp.is_function = is_function;
    imp.is_tls = is_tls;

    if (is_tls)
    {
      auto tls_it = tls_modules.find(imp.module);
      if (tls_it == tls_modules.end())
        tls_it = tls_modules.emplace(imp.module, next_tls_module_index++).first;
      imp.tls_module_index = tls_it->second;
    }

    const int index = static_cast<int>(m_imports.size());
    dedup.emplace(key, index);
    m_symbol_imports[i] = index;
    m_imports.push_back(std::move(imp));
  }
}

void cafe_loader::collectImportThunks()
{
  m_importThunkStart = BADADDR;
  m_importThunkEnd = BADADDR;

  if (m_imports.empty())
    return;

  auto *symbol_section = m_elf->getSymbolsSection();
  if (symbol_section == nullptr)
    return;

  const auto nsym = symbol_section->getSize() / symbol_section->sh_entsize;

  for (auto &section : m_elf->getSections())
  {
    if (section.sh_type != SHT_RELA)
      continue;

    const auto rela_count = section.getSize() / sizeof(Elf32_Rela);
    auto *relocations = reinterpret_cast<Elf32_Rela *>(section.data());
    for (size_t i = 0; i < rela_count; ++i)
    {
      auto rela = relocations[i];
      swap(rela.r_info);
      swap(rela.r_offset);
      swap(rela.r_addend);

      const uint32 type = ELF32_R_TYPE(rela.r_info);
      const uint32 sym_index = ELF32_R_SYM(rela.r_info);
      if (type != R_PPC_REL14 && type != R_PPC_REL24)
        continue;
      if (sym_index >= nsym || sym_index >= m_symbol_imports.size())
        continue;

      const int import_index = m_symbol_imports[sym_index];
      if (import_index < 0 || !m_imports[import_index].is_function)
        continue;

      const ea_t target = decode_branch_target(get_original_dword(rela.r_offset), rela.r_offset);
      if (target == BADADDR)
        continue;

      auto &imp = m_imports[import_index];
      if (imp.thunk_ea == BADADDR)
      {
        imp.thunk_ea = target;
      }
      else if (imp.thunk_ea != target)
      {
        msg("Import thunk mismatch for %s at %08X and %08X\n",
            imp.name.c_str(),
            static_cast<uint32>(imp.thunk_ea),
            static_cast<uint32>(target));
      }

      m_importThunkStart = m_importThunkStart == BADADDR
                         ? target
                         : std::min(m_importThunkStart, target);
      m_importThunkEnd = m_importThunkEnd == BADADDR
                       ? target + kImportThunkSize
                       : std::max(m_importThunkEnd, target + kImportThunkSize);
    }
  }
}

ea_t cafe_loader::ensureImportThunk(size_t symbol_index, ea_t reloc_ea)
{
  if (!m_haveTextRegion || symbol_index >= m_symbol_imports.size())
    return BADADDR;

  const int import_index = m_symbol_imports[symbol_index];
  if (import_index < 0)
    return BADADDR;

  auto &imp = m_imports[import_index];
  if (!imp.is_function)
    return imp.table_ea;

  if (imp.thunk_ea == BADADDR)
    imp.thunk_ea = decode_branch_target(get_original_dword(reloc_ea), reloc_ea);

  if (imp.thunk_ea < m_textAllocBase || imp.thunk_ea >= m_textAllocEnd)
    return BADADDR;

  return imp.thunk_ea;
}

ea_t cafe_loader::resolveSymbolValue(size_t symbol_index) const
{
  auto *symbol_section = m_elf->getSymbolsSection();
  if (symbol_section == nullptr)
    return BADADDR;

  auto nsym = symbol_section->getSize() / symbol_section->sh_entsize;
  if (symbol_index >= nsym)
    return BADADDR;

  if (symbol_index < m_symbol_imports.size() && m_symbol_imports[symbol_index] >= 0)
  {
    const auto &imp = m_imports[m_symbol_imports[symbol_index]];
    if (imp.is_tls)
      return BADADDR;
    return imp.table_ea;
  }

  const auto &symbol = m_elf->getSymbols()[symbol_index];
  if (symbol.st_shndx == SHN_UNDEF)
    return BADADDR;
  if (symbol.st_shndx == SHN_ABS)
    return symbol.st_value;
  if (symbol.st_shndx >= m_elf->getNumSections())
    return BADADDR;

  return symbol.st_value;
}

ea_t cafe_loader::createRel24Trampoline(ea_t target)
{
  if (!m_haveTextRegion)
    return BADADDR;

  auto it = m_internalTrampolines.find(target);
  if (it != m_internalTrampolines.end())
    return it->second;

  ea_t trampoline = BADADDR;
  if (m_postTrampCursor != BADADDR
      && m_postTrampEnd != BADADDR
      && m_postTrampCursor + kRel24TrampolineSize <= m_postTrampEnd)
  {
    trampoline = m_postTrampCursor;
    m_postTrampCursor += kRel24TrampolineSize;
  }
  else if (m_preTrampCursor != BADADDR
           && m_preTrampStart != BADADDR
           && m_preTrampCursor >= m_preTrampStart + kRel24TrampolineSize)
  {
    m_preTrampCursor -= kRel24TrampolineSize;
    trampoline = m_preTrampCursor;
  }

  if (trampoline == BADADDR)
    return BADADDR;

  patch_dword(trampoline + 0, 0x3D600000 | ((target >> 16) & 0xFFFF));
  patch_dword(trampoline + 4, 0x616B0000 | (target & 0xFFFF));
  patch_dword(trampoline + 8, 0x7D6903A6);
  patch_dword(trampoline + 12, 0x4E800420);

  m_internalTrampolines.emplace(target, trampoline);
  return trampoline;
}

int32 cafe_loader::resolveTlsModuleIndex(size_t symbol_index) const
{
  if (symbol_index < m_symbol_imports.size())
  {
    const int import_index = m_symbol_imports[symbol_index];
    if (import_index >= 0)
      return m_imports[import_index].tls_module_index;
  }

  return m_tlsModuleIndex;
}

void cafe_loader::applyRelocations()
{
  auto *symbol_section = m_elf->getSymbolsSection();
  if (symbol_section == nullptr)
    return;

  auto *symbols = m_elf->getSymbols();
  const auto nsym = symbol_section->getSize() / symbol_section->sh_entsize;
  const char *symbol_names = m_elf->getSections()[symbol_section->sh_link].data();

  for (auto &section : m_elf->getSections())
  {
    if (section.sh_type != SHT_RELA)
      continue;

    const auto rela_count = section.getSize() / sizeof(Elf32_Rela);
    auto *relocations = reinterpret_cast<Elf32_Rela *>(section.data());
    for (size_t i = 0; i < rela_count; ++i)
    {
      auto rela = relocations[i];
      swap(rela.r_info);
      swap(rela.r_offset);
      swap(rela.r_addend);

      const uint32 type = ELF32_R_TYPE(rela.r_info);
      const uint32 sym_index = ELF32_R_SYM(rela.r_info);
      if (type == R_PPC_NONE)
        continue;
      if (sym_index >= nsym)
        continue;

      const auto &symbol = symbols[sym_index];
      const int import_index = sym_index < m_symbol_imports.size()
                             ? m_symbol_imports[sym_index]
                             : -1;
      const bool imported_symbol = import_index >= 0;
      const bool imported_function = imported_symbol && m_imports[import_index].is_function;
      const bool imported_tls = imported_symbol && m_imports[import_index].is_tls;
      ea_t symbol_value = resolveSymbolValue(sym_index);
      const bool weak = ELF32_ST_BIND(symbol.st_info) == STB_WEAK;
      const bool undef_placeholder =
        symbol.st_shndx == SHN_UNDEF
        && symbol.st_name != 0
        && symbol_names != nullptr
        && std::strcmp(&symbol_names[symbol.st_name], "$UNDEF") == 0;
      const bool allow_unresolved_tls =
        imported_tls && (type == R_PPC_DTPMOD32 || type == R_PPC_DTPREL32);
      if (symbol_value == BADADDR && !weak && !undef_placeholder && !allow_unresolved_tls)
      {
        const char *name = symbol_names != nullptr && symbol.st_name != 0
                         ? &symbol_names[symbol.st_name]
                         : "<unnamed>";
        msg("Unhandled unresolved relocation %u for symbol %u (%s) at %08X\n",
            type,
            sym_index,
            name,
            rela.r_offset);
        continue;
      }
      if (symbol_value == BADADDR)
        symbol_value = 0;

      const ea_t value = symbol_value + rela.r_addend;
      // Let IDA build code/data xrefs during normal autoanalysis after the
      // relocated bytes are finalized. Forcing xrefs from the loader causes
      // IDA 9.3 to crash on valid PPC import-call instructions.
      switch (type)
      {
      case R_PPC_ADDR32:
        patch_dword(rela.r_offset, value);
        break;

      case R_PPC_ADDR16_LO:
        patch_word(rela.r_offset, value & 0xFFFF);
        break;

      case R_PPC_ADDR16_HI:
        patch_word(rela.r_offset, (value >> 16) & 0xFFFF);
        break;

      case R_PPC_ADDR16_HA:
        patch_word(rela.r_offset, ((value + 0x8000) >> 16) & 0xFFFF);
        break;

      case R_PPC_DTPMOD32:
      {
        if (ELF32_ST_TYPE(symbol.st_info) != STT_TLS)
          break;

        const int32 tls_module_index = resolveTlsModuleIndex(sym_index);
        patch_dword(rela.r_offset, tls_module_index >= 0 ? uint32(tls_module_index) : 0);
        break;
      }

      case R_PPC_DTPREL32:
        if (ELF32_ST_TYPE(symbol.st_info) == STT_TLS)
          patch_dword(rela.r_offset, imported_tls ? uint32(rela.r_addend) : value);
        break;

      case R_PPC_GHS_REL16_HA:
      {
        const int32 rel = static_cast<int32>(value) - static_cast<int32>(rela.r_offset);
        patch_word(rela.r_offset, ((rel + 0x8000) >> 16) & 0xFFFF);
        break;
      }

      case R_PPC_GHS_REL16_HI:
      {
        const int32 rel = static_cast<int32>(value) - static_cast<int32>(rela.r_offset);
        patch_word(rela.r_offset, (rel >> 16) & 0xFFFF);
        break;
      }

      case R_PPC_GHS_REL16_LO:
      {
        const int32 rel = static_cast<int32>(value) - static_cast<int32>(rela.r_offset);
        patch_word(rela.r_offset, rel & 0xFFFF);
        break;
      }

      case R_PPC_REL14:
      {
        ea_t branch_target = value;
        const uint32 inst = get_original_dword(rela.r_offset);
        if (imported_function)
        {
          branch_target = ensureImportThunk(sym_index, rela.r_offset);
          if (branch_target == BADADDR)
            break;
          break;
        }
        if ((weak || undef_placeholder) && symbol_value == 0)
          branch_target = rela.r_offset + rela.r_addend;

        uint16 rel_bits = 0;
        if (!calc_rel14(&rel_bits, branch_target, rela.r_offset))
          break;

        patch_dword(rela.r_offset, (inst & 0xFFBF0003) | rel_bits);
        break;
      }

      case R_PPC_REL24:
      {
        ea_t branch_target = value;
        const uint32 inst = get_original_dword(rela.r_offset);
        if (imported_function)
        {
          branch_target = ensureImportThunk(sym_index, rela.r_offset);
          if (branch_target == BADADDR)
            break;
          break;
        }
        if ((weak || undef_placeholder) && symbol_value == 0)
          branch_target = rela.r_offset + rela.r_addend;
        const ea_t resolved_target = branch_target;

        uint32 rel_bits = 0;
        if (!calc_rel24(&rel_bits, branch_target, rela.r_offset))
        {
          branch_target = createRel24Trampoline(branch_target);
          if (branch_target == BADADDR || !calc_rel24(&rel_bits, branch_target, rela.r_offset))
            break;
        }

        patch_dword(rela.r_offset, (inst & 0xFC000003) | rel_bits);
        if ((inst & 1) != 0)
          auto_make_proc(resolved_target);
        break;
      }

      case R_PPC_EMB_SDA21:
      {
        if (!m_haveFileInfo || !m_isRpx)
          break;

        const uint32 inst = get_original_dword(rela.r_offset);
        const uint32 ra = (inst >> 16) & 0x1F;
        uint32 base = 0;
        if (ra == 2)
          base = m_sda2Base;
        else if (ra == 13)
          base = m_sdaBase;
        else if (ra != 0)
          break;

        patch_dword(rela.r_offset, (inst & 0xFFFF0000) | ((value - base) & 0xFFFF));
        break;
      }

      default:
        msg("Unsupported Wii U relocation %u at %08X\n", type, rela.r_offset);
        break;
      }
    }
  }
}

void cafe_loader::processImports()
{
  if (m_imports.empty())
    return;

  std::map<std::string, netnode> modules;
  for (size_t i = 0; i < m_imports.size(); ++i)
  {
    const auto &imp = m_imports[i];
    const ea_t import_ea = imp.is_function && imp.thunk_ea != BADADDR
                         ? imp.thunk_ea
                         : imp.table_ea;
    if (import_ea == BADADDR || get_segment_ea(import_ea) == BADADDR)
      continue;

    if (!force_name(import_ea, imp.name.c_str()))
    {
      qstring alt = make_import_label(imp.module, imp.name);
      char suffix[32];
      qsnprintf(suffix, sizeof(suffix), "_%u", uint32(i));
      alt += suffix;
      force_name(import_ea, alt.c_str());
    }

    auto &node = modules[imp.module];
    if (!exist(node))
      node.create();
    set_import_name(node, import_ea, imp.name.c_str());
  }

  for (const auto &entry : modules)
    import_module(entry.first.c_str(), nullptr, entry.second, nullptr, nullptr);
}

void cafe_loader::processExports()
{
  const ea_t fexports_ea = get_segment_ea_by_name(".fexports");
  if (fexports_ea != BADADDR)
  {
    const ea_t start = fexports_ea;
    const ea_t seg_size = [&]
    {
      segment_info_t info;
      if (!get_segment_info(&info, start))
        return ea_t(0);
      return info.end_ea - info.start_ea;
    }();
    if (seg_size >= 8)
    {
      const uint32 num_exports = qmin(get_dword(start), static_cast<uint32>(seg_size / 8) - 1);

      for (uint32 i = 0; i < num_exports + 1; ++i)
      {
        create_dword(start + (i * 8) + 0, 4);
        create_dword(start + (i * 8) + 4, 4);

        if (i == 0)
          continue;

        const uint32 addr = get_dword(start + (i * 8) + 0);
        const uint32 name = get_dword(start + (i * 8) + 4) & 0x7FFFFFFF;
        if (name >= seg_size || get_segment_ea(addr) == BADADDR)
          continue;

        auto_make_proc(addr);

        qstring exp;
        get_strlit_contents(
          &exp,
          start + name,
          get_max_strlit_length(start + name, STRTYPE_C),
          STRTYPE_C);
        if (!exp.empty())
          add_entry(addr, addr, exp.c_str(), true);
      }
    }
  }

  const ea_t dexports_ea = get_segment_ea_by_name(".dexports");
  if (dexports_ea != BADADDR)
  {
    const ea_t start = dexports_ea;
    const ea_t seg_size = [&]
    {
      segment_info_t info;
      if (!get_segment_info(&info, start))
        return ea_t(0);
      return info.end_ea - info.start_ea;
    }();
    if (seg_size >= 8)
    {
      const uint32 num_exports = qmin(get_dword(start), static_cast<uint32>(seg_size / 8) - 1);

      for (uint32 i = 0; i < num_exports + 1; ++i)
      {
        create_dword(start + (i * 8) + 0, 4);
        create_dword(start + (i * 8) + 4, 4);

        if (i == 0)
          continue;

        const uint32 addr = get_dword(start + (i * 8) + 0);
        const uint32 name = get_dword(start + (i * 8) + 4) & 0x7FFFFFFF;
        if (name >= seg_size || get_segment_ea(addr) == BADADDR)
          continue;

        qstring exp;
        get_strlit_contents(
          &exp,
          start + name,
          get_max_strlit_length(start + name, STRTYPE_C),
          STRTYPE_C);
        if (!exp.empty())
          add_entry(addr, addr, exp.c_str(), false);
      }
    }
  }
}

void cafe_loader::swapSymbols()
{
  auto *section = m_elf->getSymbolsSection();
  if (section == nullptr)
    return;

  msg("Swapping symbols...\n");

  auto *symbols = m_elf->getSymbols();
  const auto nsym = section->getSize() / section->sh_entsize;
  for (size_t i = 0; i < nsym; ++i)
  {
    auto *symbol = &symbols[i];
    swap(symbol->st_name);
    swap(symbol->st_shndx);
    swap(symbol->st_size);
    swap(symbol->st_value);
  }
}

void cafe_loader::applySymbols()
{
  auto *section = m_elf->getSymbolsSection();
  if (section == nullptr)
    return;

  msg("Applying symbols...\n");

  auto nsym = section->getSize() / section->sh_entsize;
  auto *symbols = m_elf->getSymbols();
  const char *string_table = m_elf->getSections()[section->sh_link].data();

  for (size_t i = 0; i < nsym; ++i)
  {
    const auto &symbol = symbols[i];
    if (symbol.st_name == 0)
      continue;
    if (symbol.st_shndx == SHN_ABS || symbol.st_shndx == SHN_UNDEF)
      continue;
    if (get_segment_ea(symbol.st_value) == BADADDR)
      continue;
    if (isImportSection(symbol.st_shndx))
      continue;
    if ((m_elf->getSections()[symbol.st_shndx].sh_flags & SHF_ALLOC) == 0)
      continue;

    const char *name = &string_table[symbol.st_name];
    if (std::strcmp(name, "main") == 0 || std::strcmp(name, "_main") == 0)
      continue;

    const uint32 type = ELF32_ST_TYPE(symbol.st_info);
    switch (type)
    {
    case STT_OBJECT:
      force_name(symbol.st_value, name);
      break;

    case STT_FILE:
      add_extra_line(symbol.st_value, true, "Source File: %s", name);
      break;

    case STT_FUNC:
      force_name(symbol.st_value, name);
      auto_make_proc(symbol.st_value);
      break;
    }
  }
}
