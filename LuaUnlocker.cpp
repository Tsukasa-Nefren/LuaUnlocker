#include <stdio.h>
#include "LuaUnlocker.h"
#include <sh_memory.h>

#ifdef _WIN32
  #include <Windows.h>
  #include <Psapi.h>
  #pragma comment(lib, "Psapi.lib")
#elif __linux__
  #ifndef _GNU_SOURCE
  #define _GNU_SOURCE
  #endif
  #include <dlfcn.h>
  #include <link.h>
#endif

LuaUnlocker g_LuaUnlocker;

struct PatchPattern {
    const unsigned char* signature;
    const char* pattern;
    int offset;
    const char* description;
};

#ifdef _WIN32
static const PatchPattern patterns[] = {
    {
        (unsigned char*)"\xBE\x01\x2A\x2A\x2A\x2B\xD6\x74\x2A\x3B\xD6",
        "xx???xxx?xx",
        1,
        "Original pattern"
    },
};
#elif __linux__
static const PatchPattern patterns[] = {
    {
        (unsigned char*)"\x83\xFE\x01\x0F\x84\x2A\x2A\x2A\x2A\x83",
        "xxxxx????x",
        2,
        "Original pattern"
    },
};
#endif

#ifdef __linux__
struct DlPhdrInfo
{
    uintptr_t base;
    size_t size;
    const char* name;
};

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    DlPhdrInfo* out = static_cast<DlPhdrInfo*>(data);
    if (strstr(info->dlpi_name, out->name)) {
        out->base = info->dlpi_addr;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
            if (phdr->p_type == PT_LOAD) {
                size_t segment_end = phdr->p_vaddr + phdr->p_memsz;
                if (segment_end > out->size) {
                    out->size = segment_end;
                }
            }
        }
        return 1;
    }
    return 0;
}
#endif

uintptr_t FindPattern(uintptr_t BaseAddr, const unsigned char* pData, const char* pPattern, size_t MaxSize, bool Reverse)
{
  unsigned char* pMemory;
  uintptr_t PatternLen = strlen(pPattern);

  pMemory = reinterpret_cast<unsigned char*>(BaseAddr);

  if (!Reverse)
  {
    for (uintptr_t i = 0; i + PatternLen <= MaxSize; i++)
    {
      uintptr_t Matches = 0;
      while (*(pMemory + i + Matches) == pData[Matches] || pPattern[Matches] != 'x')
      {
        Matches++;
        if (Matches == PatternLen)
          return (uintptr_t)(pMemory + i);
      }
    }
  }
  else
  {
    for (uintptr_t i = 0; i < MaxSize; i++)
    {
      uintptr_t Matches = 0;
      while (*(pMemory - i + Matches) == pData[Matches] || pPattern[Matches] != 'x')
      {
        Matches++;
        if (Matches == PatternLen)
          return (uintptr_t)(pMemory - i);
      }
    }
  }

  return 0x00;
}

PLUGIN_EXPOSE(LuaUnlocker, g_LuaUnlocker);
bool LuaUnlocker::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
  PLUGIN_SAVEVARS();

  char pBinPath[MAX_PATH];
#ifdef _WIN32
  V_snprintf(pBinPath, MAX_PATH, "%s%s", Plat_GetGameDirectory(), "/bin/win64/vscript.dll");
  auto *pBin = LoadLibrary(pBinPath);
#elif __linux__
  V_snprintf(pBinPath, MAX_PATH, "%s%s", Plat_GetGameDirectory(), "/bin/linuxsteamrt64/libvscript.so");
  auto *pBin = dlopen(pBinPath, RTLD_NOW);
#endif

  if (!pBin)
  {
    snprintf(error, maxlen, "Could not open %s", pBinPath);
    return false;
  }

  uintptr_t pPatchAddress = 0;
  int patchOffset = 0;

#ifdef _WIN32
  MODULEINFO mi{};
  if (!GetModuleInformation(GetCurrentProcess(), (HMODULE)pBin, &mi, sizeof(mi))) {
    snprintf(error, maxlen, "GetModuleInformation failed for %s", pBinPath);
    return false;
  }

  uintptr_t moduleBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
  size_t    moduleSize = static_cast<size_t>(mi.SizeOfImage);
  
  const unsigned char* movEax2Pattern = (unsigned char*)"\xB8\x02\x00\x00\x00";
  const char* movEax2Mask = "xxxxx";
  uintptr_t movEax2Addr = FindPattern(moduleBase, movEax2Pattern, movEax2Mask, moduleSize, false);
  
  const unsigned char* movEsi2Pattern = (unsigned char*)"\xBE\x02\x00\x00\x00";
  const char* movEsi2Mask = "xxxxx";
  uintptr_t movEsi2Addr = FindPattern(moduleBase, movEsi2Pattern, movEsi2Mask, moduleSize, false);
  
  if (movEax2Addr) {
    pPatchAddress = movEax2Addr;
    patchOffset = 1;
  } else if (movEsi2Addr) {
    pPatchAddress = movEsi2Addr;
    patchOffset = 1;
  }
  
  if (!pPatchAddress) {
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
      pPatchAddress = FindPattern(moduleBase, patterns[i].signature, patterns[i].pattern, moduleSize, false);
      if (pPatchAddress) {
        patchOffset = patterns[i].offset;
        break;
      }
    }
  }

#elif __linux__
  DlPhdrInfo info = { 0, 0, "libvscript.so" };
  dl_iterate_phdr(phdr_callback, &info);

  if (info.base == 0 || info.size == 0) {
      snprintf(error, maxlen, "Could not get module information for %s", pBinPath);
      dlclose(pBin);
      return false;
  }

  const unsigned char* movEax2Pattern = (unsigned char*)"\xB8\x02\x00\x00\x00";
  const char* movEax2Mask = "xxxxx";
  uintptr_t movEax2Addr = FindPattern(info.base, movEax2Pattern, movEax2Mask, info.size, false);
  
  const unsigned char* movEsi2Pattern = (unsigned char*)"\xBE\x02\x00\x00\x00";
  const char* movEsi2Mask = "xxxxx";
  uintptr_t movEsi2Addr = FindPattern(info.base, movEsi2Pattern, movEsi2Mask, info.size, false);
  
  if (movEax2Addr) {
    pPatchAddress = movEax2Addr;
    patchOffset = 1;
  } else if (movEsi2Addr) {
    pPatchAddress = movEsi2Addr;
    patchOffset = 1;
  }
  
  if (!pPatchAddress) {
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
      pPatchAddress = FindPattern(info.base, patterns[i].signature, patterns[i].pattern, info.size, false);
      if (pPatchAddress) {
        patchOffset = patterns[i].offset;
        break;
      }
    }
  }
#endif

  if (!pPatchAddress)
  {
    snprintf(error, maxlen, "Could not find VScript patch signature!");
    return false;
  }

  SourceHook::SetMemAccess((void*)(pPatchAddress + patchOffset), 1, SH_MEM_READ | SH_MEM_WRITE | SH_MEM_EXEC);
  *(unsigned char*)(pPatchAddress + patchOffset) = 0x01;
  SourceHook::SetMemAccess((void*)(pPatchAddress + patchOffset), 1, SH_MEM_READ | SH_MEM_EXEC);

  return true;
}

bool LuaUnlocker::Unload(char *error, size_t maxlen)
{
  return true;
}

void LuaUnlocker::AllPluginsLoaded()
{
}

bool LuaUnlocker::Pause(char *error, size_t maxlen)
{
  return true;
}

bool LuaUnlocker::Unpause(char *error, size_t maxlen)
{
  return true;
}

const char * LuaUnlocker::GetLicense()
{
  return "GNU General Public License v3.0";
}

const char * LuaUnlocker::GetVersion()
{
  return "1.0";
}

const char * LuaUnlocker::GetDate()
{
  return __DATE__;
}

const char * LuaUnlocker::GetLogTag()
{
  return "LUAUNLOCKER";
}

const char * LuaUnlocker::GetAuthor()
{
  return "Hichatu";
}

const char * LuaUnlocker::GetDescription()
{
  return "Enables the use of the Lua VScripting language in CS2";
}

const char * LuaUnlocker::GetName()
{
  return "Lua Unlocker";
}

const char * LuaUnlocker::GetURL()
{
  return "https://github.com/Source2ZE/LuaUnlocker";
}
