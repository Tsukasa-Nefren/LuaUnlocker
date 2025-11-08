// Stolen entirely from https://github.com/Source2ZE/MovementUnlocker
// Edited for unlocking Lua
// With lots of help from Vauff & tilgep

#include <stdio.h>
#include "LuaUnlocker.h"
#include <sh_memory.h>

#ifdef _WIN32
  #include <Windows.h>
  #include <Psapi.h>              // for GetModuleInformation
  #pragma comment(lib, "Psapi.lib")
#elif __linux__
  #ifndef _GNU_SOURCE
  #define _GNU_SOURCE
  #endif
  #include <dlfcn.h>
  #include <link.h>
#endif

LuaUnlocker g_LuaUnlocker;

// 패턴 구조체: 여러 패턴을 시도할 수 있도록
struct PatchPattern {
    const unsigned char* signature;
    const char* pattern;
    int offset;
    const char* description;
};

#ifdef _WIN32
// 원래 패턴
static const PatchPattern patterns[] = {
    {
        (unsigned char*)"\xBE\x01\x2A\x2A\x2A\x2B\xD6\x74\x2A\x3B\xD6",
        "xx???xxx?xx",
        1,
        "Original pattern"
    },
    // 새로운 패턴들을 여기에 추가할 수 있습니다
    // 예: {
    //     (unsigned char*)"\xXX\xXX...",
    //     "xx...",
    //     1,
    //     "New pattern after update"
    // },
};
#elif __linux__
static const PatchPattern patterns[] = {
    {
        (unsigned char*)"\x83\xFE\x01\x0F\x84\x2A\x2A\x2A\x2A\x83",
        "xxxxx????x",
        2,
        "Original pattern"
    },
    // 새로운 패턴들을 여기에 추가할 수 있습니다
};
#endif

#ifdef __linux__
// 콜백 함수와 데이터 저장을 위한 구조체
struct DlPhdrInfo
{
    uintptr_t base;
    size_t size;
    const char* name;
};

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    DlPhdrInfo* out = static_cast<DlPhdrInfo*>(data);
    // V_stristr은 Source SDK의 문자열 검색 함수입니다.
    if (strstr(info->dlpi_name, out->name)) {
        out->base = info->dlpi_addr;
        // 모든 프로그램 헤더를 순회하며 가장 큰 주소 + 크기를 찾아 전체 이미지 크기를 계산
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
            if (phdr->p_type == PT_LOAD) {
                size_t segment_end = phdr->p_vaddr + phdr->p_memsz;
                if (segment_end > out->size) {
                    out->size = segment_end;
                }
            }
        }
        return 1; // 검색 중단
    }
    return 0;
}
#endif

// From https://git.botox.bz/CSSZombieEscape/sm-ext-PhysHooks
uintptr_t FindPattern(uintptr_t BaseAddr, const unsigned char* pData, const char* pPattern, size_t MaxSize, bool Reverse)
{
  unsigned char* pMemory;
  uintptr_t PatternLen = strlen(pPattern);

  pMemory = reinterpret_cast<unsigned char*>(BaseAddr);

  if (!Reverse)
  {
    // Forward scan, keep within [0, MaxSize - PatternLen]
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
    // Reverse scan (used by original Linux path). Bounds are not known, caller must ensure safety.
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

#ifdef _WIN32
  // Scan the entire vscript.dll image for the signature (safer than scanning relative to CreateInterface).
  MODULEINFO mi{};
  if (!GetModuleInformation(GetCurrentProcess(), (HMODULE)pBin, &mi, sizeof(mi))) {
    snprintf(error, maxlen, "GetModuleInformation failed for %s", pBinPath);
    return false;
  }

  uintptr_t moduleBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
  size_t    moduleSize = static_cast<size_t>(mi.SizeOfImage);

  META_CONPRINTF("[Lua Unlocker] Scanning vscript.dll: base=0x%p size=0x%zx\n",
                 (void*)moduleBase, moduleSize);

  // ModSharp 방식: 여러 패턴을 시도
  uintptr_t pPatchAddress = 0;
  int patchOffset = 0;
  const char* usedPattern = nullptr;
  
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    pPatchAddress = FindPattern(moduleBase, patterns[i].signature, patterns[i].pattern, moduleSize, /*Reverse=*/false);
    if (pPatchAddress) {
      patchOffset = patterns[i].offset;
      usedPattern = patterns[i].description;
      META_CONPRINTF("[Lua Unlocker] Found pattern '%s' at 0x%p (offset 0x%x).\n",
                     usedPattern, (void*)pPatchAddress, patchOffset);
      break;
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

  META_CONPRINTF("[Lua Unlocker] Scanning libvscript.so: base=0x%p size=0x%zx\n",
                 (void*)info.base, info.size);

  // ModSharp 방식: 여러 패턴을 시도
  uintptr_t pPatchAddress = 0;
  int patchOffset = 0;
  const char* usedPattern = nullptr;
  
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    pPatchAddress = FindPattern(info.base, patterns[i].signature, patterns[i].pattern, info.size, /*Reverse=*/false);
    if (pPatchAddress) {
      patchOffset = patterns[i].offset;
      usedPattern = patterns[i].description;
      META_CONPRINTF("[Lua Unlocker] Found pattern '%s' at 0x%p (offset 0x%x).\n",
                     usedPattern, (void*)pPatchAddress, patchOffset);
      break;
    }
  }
#endif

  if (!pPatchAddress)
  {
    // ModSharp 방식: MOV EAX, 2 패턴을 직접 찾기 시도
    // Windows: B8 02 00 00 00 (MOV EAX, 2) 또는 BE 02 00 00 00 (MOV ESI, 2)
    // Linux: B8 02 00 00 00 (MOV EAX, 2) 또는 BE 02 00 00 00 (MOV ESI, 2)
    META_CONPRINTF("[Lua Unlocker] Trying ModSharp-style pattern matching...\n");
    
#ifdef _WIN32
    // MOV EAX, 2 패턴 찾기: B8 02 00 00 00
    const unsigned char* movEax2Pattern = (unsigned char*)"\xB8\x02\x00\x00\x00";
    const char* movEax2Mask = "xxxxx";
    uintptr_t movEax2Addr = FindPattern(moduleBase, movEax2Pattern, movEax2Mask, moduleSize, false);
    
    // MOV ESI, 2 패턴 찾기: BE 02 00 00 00
    const unsigned char* movEsi2Pattern = (unsigned char*)"\xBE\x02\x00\x00\x00";
    const char* movEsi2Mask = "xxxxx";
    uintptr_t movEsi2Addr = FindPattern(moduleBase, movEsi2Pattern, movEsi2Mask, moduleSize, false);
    
    if (movEax2Addr) {
      pPatchAddress = movEax2Addr;
      patchOffset = 1; // 02를 01로 변경
      usedPattern = "ModSharp-style MOV EAX, 2";
      META_CONPRINTF("[Lua Unlocker] Found ModSharp pattern (MOV EAX, 2) at 0x%p\n", (void*)pPatchAddress);
    } else if (movEsi2Addr) {
      pPatchAddress = movEsi2Addr;
      patchOffset = 1; // 02를 01로 변경
      usedPattern = "ModSharp-style MOV ESI, 2";
      META_CONPRINTF("[Lua Unlocker] Found ModSharp pattern (MOV ESI, 2) at 0x%p\n", (void*)pPatchAddress);
    }
#elif __linux__
    // Linux에서도 동일한 패턴 시도
    const unsigned char* movEax2Pattern = (unsigned char*)"\xB8\x02\x00\x00\x00";
    const char* movEax2Mask = "xxxxx";
    uintptr_t movEax2Addr = FindPattern(info.base, movEax2Pattern, movEax2Mask, info.size, false);
    
    const unsigned char* movEsi2Pattern = (unsigned char*)"\xBE\x02\x00\x00\x00";
    const char* movEsi2Mask = "xxxxx";
    uintptr_t movEsi2Addr = FindPattern(info.base, movEsi2Pattern, movEsi2Mask, info.size, false);
    
    if (movEax2Addr) {
      pPatchAddress = movEax2Addr;
      patchOffset = 1;
      usedPattern = "ModSharp-style MOV EAX, 2";
      META_CONPRINTF("[Lua Unlocker] Found ModSharp pattern (MOV EAX, 2) at 0x%p\n", (void*)pPatchAddress);
    } else if (movEsi2Addr) {
      pPatchAddress = movEsi2Addr;
      patchOffset = 1;
      usedPattern = "ModSharp-style MOV ESI, 2";
      META_CONPRINTF("[Lua Unlocker] Found ModSharp pattern (MOV ESI, 2) at 0x%p\n", (void*)pPatchAddress);
    }
#endif
  }

  if (!pPatchAddress)
  {
    // 디버깅을 위해 주변 바이트 덤프
    META_CONPRINTF("[Lua Unlocker] Could not find VScript patch signature!\n");
    META_CONPRINTF("[Lua Unlocker] Please check vscript.dll/libvscript.so for MOV EAX, 2 or MOV ESI, 2 patterns.\n");
    snprintf(error, maxlen, "Could not find VScript patch signature! Tried %zu patterns.", sizeof(patterns) / sizeof(patterns[0]));
    return false;
  }

  // 패치 전 값 확인
  unsigned char originalValue = *(unsigned char*)(pPatchAddress + patchOffset);
  META_CONPRINTF("[Lua Unlocker] Original value at 0x%p+0x%x: 0x%02X\n", 
                 (void*)pPatchAddress, patchOffset, originalValue);

  // ModSharp 방식: 2를 1로 변경 (VScript 활성화)
  SourceHook::SetMemAccess((void*)(pPatchAddress + patchOffset), 1, SH_MEM_READ | SH_MEM_WRITE | SH_MEM_EXEC);
  *(unsigned char*)(pPatchAddress + patchOffset) = 0x01;
  SourceHook::SetMemAccess((void*)(pPatchAddress + patchOffset), 1, SH_MEM_READ | SH_MEM_EXEC);

  // 패치 후 값 확인
  unsigned char patchedValue = *(unsigned char*)(pPatchAddress + patchOffset);
  META_CONPRINTF("[Lua Unlocker] Patched value at 0x%p+0x%x: 0x%02X (was 0x%02X)\n", 
                 (void*)pPatchAddress, patchOffset, patchedValue, originalValue);
  META_CONPRINTF("[Lua Unlocker] Successfully patched Lua Unlocker using pattern: %s\n", usedPattern);

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
