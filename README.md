# Overview
INTRACTABLEGIRAFFE is a proof of concept rootkit developed to demonstrate the usage of a hidden Virtual File System (VFS) to store files outside of the standard Windows file system. The design of INTRACTABLEGRAFFE is inspired by the Uroburos rootkit [1], which implements both a volatile and a non-volatile hidden VFS. INTRACTABLEGIRAFFE supports loading by the "Turla Driver Loader" tool developed by hFiref0x/EP_X0FF on 64-bit operating systems to bypass driver signature enforcement. 

# Components
INTRACTABLEGIRAFFE has three primary components: a volatile VFS, non-volatile VFS, and a keylogger leveraged to capture keystrokes entered by the user. Component descriptions are as follows:
* Volatile VFS: Stores the VFS data within the non-paged pool and doesn’t persist any of the corresponding filesystem data to disk.
* Non-Volatile VFS: Stores the VFS data within a file on the filesystem which contains the hidden file system embedded within it. 
* Keylogger: They keylogger is a standard KeyboardClass0 keylogger that captures keystrokes. It layers on top of the keyboard driver to register an IoCompletionRoutine, which enables it to capture keystrokes after the underlying device reads them.

# More Information

For more information on INTRACTABLEGIRAFFE including usage instructions, key design considerations, and potential future expansion work, please see the blog post we have published entitled [Developing a Hidden Virtual File System Capability That Emulates the Uroburos Rootkit](https://www.praetorian.com/blog/developing-a-vfs-that-emulates-uroburos-rootkit).
