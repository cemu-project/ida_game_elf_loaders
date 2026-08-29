#pragma once

#include "elf_reader.h"
#include "cafe.h"

#include <map>
#include <string>
#include <vector>

class cafe_loader {
  elf_reader<elf32> *m_elf;

  struct import {
    uint32 symbol_index;
    ea_t table_ea;
    ea_t thunk_ea;
    std::string module;
    std::string name;
    int32 tls_module_index;
    bool is_function;
    bool is_tls;
  };

  std::vector<import> m_imports;
  std::map<ea_t, ea_t> m_internalTrampolines;
  std::vector<int> m_symbol_imports;

  uint32 m_sdaBase;
  uint32 m_sda2Base;
  uint32 m_textSize;
  uint32 m_trampAdjust;
  int32 m_tlsModuleIndex;
  bool m_haveFileInfo;
  bool m_haveTextRegion;
  bool m_isRpx;
  ea_t m_textAllocBase;
  ea_t m_textAllocEnd;
  ea_t m_textLoadStart;
  ea_t m_textLoadEnd;
  ea_t m_importThunkStart;
  ea_t m_importThunkEnd;
  ea_t m_preTrampStart;
  ea_t m_preTrampCursor;
  ea_t m_postTrampCursor;
  ea_t m_postTrampEnd;
  
public:
  cafe_loader(elf_reader<elf32> *elf);
  
  void apply();
  
private:
  void applySegments();
  void applySegment(uint32 sel,
                    const char *data,
                    uint32 addr,
                    uint32 size,
                    const char *name,
                    const char *sclass,
                    uchar perm,
                    uchar align,
                    bool load);

  void collectFileInfo();
  void collectImports();
  void collectImportThunks();
  void createTextTrampolineSegments();
  bool isImportSection(uint16 section_index) const;
  ea_t ensureImportThunk(size_t symbol_index, ea_t reloc_ea);
  ea_t resolveSymbolValue(size_t symbol_index) const;
  ea_t createRel24Trampoline(ea_t target);
  int32 resolveTlsModuleIndex(size_t symbol_index) const;

  void applyRelocations();

  void processImports();
  void processExports();
  void processExportTable(const char *segname, bool makecode);
  void swapSymbols();
  void applySymbols();
};
