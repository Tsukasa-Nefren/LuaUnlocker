//Stolen entirely from https://github.com/Source2ZE/MovementUnlocker
//Edited for unlocking Lua
//With lots of help from Vauff & tilgep

#include <stdio.h>
#include "LuaUnlocker.h"
#include <sh_memory.h>

#ifdef _WIN32
  #include <Windows.h>
  #include <Psapi.h>              // for GetModuleInformation
  #pragma comment(lib, "Psapi.lib")
#elif __linux__
  #include <dlfcn.h>
#endif

LuaUnlocker g_LuaUnlocker;

#ifdef _WIN32
const unsigned char* pPatchSignature = (unsigned char*)
    "\xBE\x01\x2A\x2A\x2A\x2B\xD6\x74\x2A\x3B\xD6";
const char* pPatchPattern = "xx???xxx?xx";
int offset = 1;
#elif __linux__
const unsigned char * pPatchSignature = (unsigned char *)
    "\x83\xFE\x01\x0F\x84\x2A\x2A\x2A\x2A\x83";
const char* pPatchPattern = "xxxxx????x";
int offset = 2;
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

  uintptr_t pPatchAddress = FindPattern(moduleBase, pPatchSignature, pPatchPattern, moduleSize, /*Reverse=*/false);

#elif __linux__
  // Original behavior (Linux): start from CreateInterface and search backwards.
  uintptr_t pPatchAddress = (uintptr_t)dlsym(pBin, "CreateInterface");
  pPatchAddress = FindPattern(pPatchAddress, pPatchSignature, pPatchPattern, ULLONG_MAX, true);
#endif

  if (pPatchAddress) {
    META_CONPRINTF("[Lua Unlocker] Found VScript patch signature at 0x%p (offset 0x%x).\n",
                   (void*)pPatchAddress, offset);
  }

  if (!pPatchAddress)
  {
    snprintf(error, maxlen, "Could not find VScript patch signature!");
    return false;
  }

  // Patch
  SourceHook::SetMemAccess((void*)(pPatchAddress + offset), 1, SH_MEM_READ | SH_MEM_WRITE | SH_MEM_EXEC);
  *(unsigned char*)(pPatchAddress + offset) = ((unsigned char*)"\x02")[0];
  SourceHook::SetMemAccess((void*)(pPatchAddress + offset), 1, SH_MEM_READ | SH_MEM_EXEC);

  META_CONPRINTF("[Lua Unlocker] Successfully patched Lua Unlocker!\n");

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
