// Leak detection is not a bug class this fleet fuzzes for: turn LeakSanitizer off at build time while
// keeping ASan and UBSan fully active (SPEC §6.2 item 15).
extern "C" int __lsan_is_turned_off() { return 1; }
