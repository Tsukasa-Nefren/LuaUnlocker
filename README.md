#Check actions tab!
[Actions](https://github.com/Tsukasa-Nefren/LuaUnlocker/actions)


# Lua Unlocker

## WARNING: Lua VScript is intentionally disabled by Valve! It is expected to be replaced by Pulse in the future, and will likely be completely removed from the game when that happens. Depend on Lua at your own risk.

Enables the Lua VScripting language, now as a Metamod plugin!

## Installation

- Install [Metamod](https://cs2.poggu.me/metamod/installation/)
- Download the [latest release package](https://github.com/Source2ZE/LuaUnlocker/releases/latest) for your OS
- Extract the package contents into `game/csgo` on your server

## Build Instructions

### Windows
```bash
git clone https://github.com/Source2ZE/LuaUnlocker/ && cd LuaUnlocker

setx MMSOURCE112=/path/to/metamod/
setx HL2SDKCS2=/path/to/sdk/submodule

mkdir build && cd build
python ../configure.py -s cs2
ambuild
```

### Linux
```bash
git clone https://github.com/Source2ZE/LuaUnlocker/ && cd LuaUnlocker

export MMSOURCE112=/path/to/metamod/
export HL2SDKCS2=/path/to/sdk/submodule

mkdir build && cd build
python3 ../configure.py -s cs2
ambuild
```
