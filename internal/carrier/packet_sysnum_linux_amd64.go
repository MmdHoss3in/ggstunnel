package carrier

// The frozen syscall package omits this amd64 entry. Linux syscall_64.tbl:
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
const bipSendMmsg = 307
