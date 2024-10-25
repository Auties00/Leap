#include <fcntl.h>
#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// C blocks are not part of the standard C spec
// For this reason, CLang executes a desugar routine that transforms code blocks into structures
// This structure should match CLang's implementation for blocks that don't capture context from the method
// This can be verified by reading the source code at https://github.com/hdoc/llvm-project
struct __Block_byref_ND { // Kind of inferred from debugging using CLion and reading comments in the llvm-project
    void * __isa;
    int __flags;
    int __reserved;
    void * __FuncPtr;
};
enum BlockByrefFlags { // https://github.com/hdoc/llvm-project/blob/release/15.x//clang/lib/CodeGen/CGBlocks.h#L38
  BLOCK_BYREF_HAS_COPY_DISPOSE         = (1   << 25), // compiler
  BLOCK_BYREF_LAYOUT_MASK              = (0xF << 28), // compiler
  BLOCK_BYREF_LAYOUT_EXTENDED          = (1   << 28),
  BLOCK_BYREF_LAYOUT_NON_OBJECT        = (2   << 28),
  BLOCK_BYREF_LAYOUT_STRONG            = (3   << 28),
  BLOCK_BYREF_LAYOUT_WEAK              = (4   << 28),
  BLOCK_BYREF_LAYOUT_UNRETAINED        = (5   << 28)
};