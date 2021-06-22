
set(HUNTER_CONFIGURATION_TYPES Release
    CACHE STRING "Build type of the Hunter packages")

include(HunterGate)

HunterGate(
    URL "https://github.com/FISCO-BCOS/hunter/archive/f88ce89a9fcd557b7fb2aa0f7abaa3c541dc6903.tar.gz"
    SHA1 "b7792231bf64539602e696e32bfc163c9bc1812a"
    LOCAL
)
