#include <idc.idc>
static main() {
  auto_wait();
  load_and_run_plugin("binexport12_ida", 2);
  qexit(0);
}