/* Test wrapper: mode 1 (KeyGen) via combined binary dispatch */
.text
.globl _start
_start:
  la    x3, mode
  li    x4, 1
  sw    x4, 0(x3)
  jal   x1, main
