use core::time::Duration;
use std::fmt;
use std::fs;
use std::ops::Index;
use std::ops::*;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::str::FromStr;
use std::sync::mpsc::Receiver as SyncReceiver;
use std::sync::mpsc::Sender as SyncSender;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[allow(dead_code)]
pub enum What {
    Rename,
    Modify,
    Create,
    Destroy,
    Owner,
    Other,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[allow(dead_code)]
pub enum Kind {
    Dir,
    File,
    HardLink,
    SymLink,
    Watcher,
    Other,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Event {
    pub path: Box<Path>,
    pub what: What,
    pub kind: Kind,
    pub when: Duration,
}

impl fmt::Display for What {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            What::Rename => write!(f, "rename"),
            What::Modify => write!(f, "modify"),
            What::Create => write!(f, "create"),
            What::Destroy => write!(f, "destroy"),
            What::Owner => write!(f, "owner"),
            What::Other => write!(f, "other"),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Kind::Dir => write!(f, "dir"),
            Kind::File => write!(f, "file"),
            Kind::HardLink => write!(f, "hard_link"),
            Kind::SymLink => write!(f, "sym_link"),
            Kind::Watcher => write!(f, "watcher"),
            Kind::Other => write!(f, "other"),
        }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            r#""{}":{{"where":"{}","what":"{}","kind":"{}"}}"#,
            self.when.as_nanos(),
            self.path.to_string_lossy(),
            self.what,
            self.kind,
        )
    }
}

#[allow(dead_code)]
pub mod sys {
    pub use core::ffi::*;
    use core::ptr::null_mut;
    pub const NULLPTR: *mut c_void = null_mut();
    pub mod os {
        pub mod linux {
            use super::super::*;
            pub const IN_CREATE: u32 = 0x00000100;
            pub const IN_MODIFY: u32 = 0x00000002;
            pub const IN_DELETE: u32 = 0x00000200;
            pub const IN_ISDIR: u32 = 0x40000000;
            pub const IN_Q_OVERFLOW: u32 = 0x00004000;
            pub const IN_MOVED_FROM: u32 = 0x00000040;
            pub const IN_MOVED_TO: u32 = 0x00000080;
            pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;

            // int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
            extern "C" {
                pub fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int;
            }
        }
    }
}

type PathMap = std::collections::HashMap<i32, String>;

fn path_map(base_path: &std::path::Path, watch_fd: RawFd) -> PathMap {
    use sys::os::linux::*;

    // Follow symlinks, ignore paths which we don't have permissions for.
    const PATH_MAP_RESERVE_COUNT: usize = 256;
    const IN_WATCH_OPT: u32 = IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_Q_OVERFLOW;

    let mut pm = PathMap::new();
    pm.reserve(PATH_MAP_RESERVE_COUNT);

    let mut do_mark = |dir: &std::path::Path| {
        if dir.is_dir() {
            // let dir_cstr = dir.to_str().unwrap_or(".").to_string().as_bytes().as_ptr() as *const i8;
            let mut dir_cstr: Vec<u8> = dir.clone().to_str().unwrap().as_bytes().to_vec();
            dir_cstr.push(b'\0');
            // let tmp2 = &core::ffi::CStr::from_(tmp);
            let wd = unsafe {
                inotify_add_watch(watch_fd, dir_cstr.as_ptr() as *const i8, IN_WATCH_OPT)
            };
            if wd > 0 {
                pm.insert(wd, dir.to_str().unwrap().to_string()).is_some()
            } else {
                println!(
                    "e/sys/inotify_add_watch@{} : from {} : {}",
                    dir.to_string_lossy(),
                    core::ffi::CStr::from_bytes_with_nul(&dir_cstr)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    strerrno()
                );
                false
            }
        } else {
            false
        }
    };

    let mut markwalk_recursive = |topdir: std::path::PathBuf| {
        do_mark(base_path);
        let mut dirvec = vec![topdir];
        let mut done = false;
        while !done {
            if let Some(nexttop) = dirvec.pop() {
                if let Ok(mut entries) = fs::read_dir(nexttop) {
                    for entry in entries.by_ref() {
                        if let Ok(dir) = entry {
                            if do_mark(&dir.path()) {
                                dirvec.push(dir.path());
                            }
                        } else {
                            done = true
                        }
                    }
                } else {
                    done = true
                }
            } else {
                done = true
            }
        }
    };

    markwalk_recursive(base_path.to_path_buf());

    pm
}

/*  @brief wtr/watcher/<d>/adapter/linux/inotify/<a>/fns/system_unfold
Produces a `sys_resource_type` with the file descriptors from
`inotify_init` and `epoll_create`. Invokes `callback` on errors. */
struct SysResource {
    valid: bool,
    watch_fd: i32,
    event_fd: i32,
    event_conf: libc::epoll_event,
}

fn system_unfold() -> SysResource {
    let do_error = |msg: &str, watch_fd: i32, event_fd: i32| -> SysResource {
        println!("{} : {}", msg, strerrno());
        SysResource {
            valid: false,
            watch_fd,
            event_fd,
            event_conf: libc::epoll_event {
                events: 0,
                u64: event_fd as u64,
            },
        }
    };

    // const IN_NONBLOCK: i32 = 0x00004000;

    let watch_fd = unsafe { libc::inotify_init() };
    // let watch_fd = unsafe { libc::inotify_init1(IN_NONBLOCK) };

    if watch_fd >= 0 {
        let mut event_conf = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: watch_fd as u64,
        };

        let event_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };

        println!("epfd {} : {}", event_fd, strerrno());

        if event_fd >= 0 {
            if unsafe { libc::epoll_ctl(event_fd, libc::EPOLL_CTL_ADD, watch_fd, &mut event_conf) }
                >= 0
            {
                return SysResource {
                    valid: true,
                    watch_fd,
                    event_fd,
                    event_conf,
                };
            } else {
                do_error("e/sys/epoll_ctl", watch_fd, event_fd)
            }
        } else {
            do_error("e/sys/epoll_create", watch_fd, event_fd)
        }
    } else {
        do_error("e/sys/inotify_init", watch_fd, -1)
    }
}

fn system_fold(sr: SysResource) -> bool {
    return unsafe { libc::close(sr.watch_fd) + libc::close(sr.event_fd) } == 0;
}

enum EventRecvState {
    Eventful,
    Eventless,
    Error,
}

fn now() -> std::time::Duration {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since_epoch) => since_epoch,
        Err(_) => std::time::Duration::from_nanos(0),
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct inotify_event {
    pub wd: core::ffi::c_int,
    pub mask: u32,
    pub cookie: u32,
    pub len: u32,
    pub name: [u8; 0],
}

fn do_event_recv(watch_fd: i32, mut pm: &mut PathMap, event_tx: SyncSender<Event>) -> bool {
    use core::ffi::c_void;
    use sys::os::linux::*;

    const EVENT_BUF_LEN: usize = 4096;
    const IN_WATCH_OPT: u32 = IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_Q_OVERFLOW;

    let buf = vec![EVENT_BUF_LEN];
    let buf_ptr = buf.as_slice().as_ptr();

    // While inotify has events pending, read them.
    // There might be several events from a single read.
    //
    // Three possible states:
    //  - eventful: there are events to read
    //  - eventless: there are no events to read
    //  - error: there was an error reading events
    //
    // The EAGAIN "error" means there is nothing
    // to read. We count that as 'eventless'.
    //
    // Forward events and errors to the user.
    //
    // Return when eventless.

    let mut should_continue = true;

    while should_continue == true {
        let read_len = unsafe { libc::read(watch_fd, buf_ptr as *mut c_void, EVENT_BUF_LEN) };

        let state = match read_len > 0 {
            true => EventRecvState::Eventful,
            false => match read_len == 0 {
                true => match std::io::Error::last_os_error().raw_os_error() {
                    Some(errno) => match errno {
                        libc::EAGAIN => EventRecvState::Eventless,
                        _ => EventRecvState::Error,
                    },
                    None => EventRecvState::Error,
                },
                false => EventRecvState::Error,
            },
        };

        should_continue = match state {
            EventRecvState::Eventful => {
                /* Loop over all events in the buffer. */
                let mut this_event_ptr = buf_ptr as *const inotify_event;
                // println!(
                //     "buf_ptr.offset_from(this_event_ptr as *const usize) : {}",
                //     unsafe { buf_ptr.offset_from(this_event_ptr as *const usize) }
                // );
                while unsafe { buf_ptr.offset_from(this_event_ptr as *const usize) } >= 0 {
                    let this_event = unsafe { &(*this_event_ptr) };

                    println!("this_event_ptr.offset_from(buf_ptr as *const inotify_event) + read_len : {}",
                             unsafe {
                                 this_event_ptr.offset_from(buf_ptr as *const inotify_event) + read_len
                             });
                    println!("read_len : {}", read_len);
                    println!("this_event.len : {}", this_event.len);
                    if (this_event.mask.bitand(IN_Q_OVERFLOW)) == 0 {
                        println!("this_event.wd : {}", this_event.wd);
                        let default_cached_base_path: String = "".to_string(); // inefficient...
                        let cached_base_path = default_cached_base_path.as_str();
                        println!("default_cached_base_path : {}", default_cached_base_path);
                        println!("cached_base_path : {}", cached_base_path);
                        let this_event_name_cstr = this_event.name.as_ptr() as *const i8;
                        let name = unsafe { core::ffi::CStr::from_ptr(this_event_name_cstr) };
                        let name_str = name.to_str().unwrap();
                        println!("name_str : {}", name_str);
                        let mut path_string: String =
                            String::from_str(cached_base_path).unwrap_or_default();
                        println!("path_string/orig : {}", path_string);
                        path_string.push_str(&name_str);
                        println!("path_string/push : {}", path_string);

                        let kind = match (this_event.mask & IN_ISDIR) != 0 {
                            true => Kind::Dir,
                            false => Kind::File,
                        };

                        let what = match (this_event.mask & IN_CREATE) != 0 {
                            true => What::Create,
                            false => match (this_event.mask & IN_DELETE) != 0 {
                                true => What::Destroy,
                                false => match (this_event.mask & IN_MOVE) != 0 {
                                    true => What::Rename,
                                    false => match (this_event.mask & IN_MODIFY) != 0 {
                                        true => What::Modify,
                                        false => What::Other,
                                    },
                                },
                            },
                        };

                        let when = now();

                        let path = std::path::PathBuf::from_str(&path_string.clone())
                            .unwrap()
                            .into_boxed_path();

                        let event = Event {
                            path,
                            what,
                            kind,
                            when,
                        };

                        println!("event: {}", event);

                        println!("do we get here? send/0");

                        event_tx.send(event).unwrap_or_else(|_| {
                            println!("{}", strerrno());
                            ()
                        });

                        println!("do we get here? send/1");

                        if kind == Kind::Dir && what == What::Create {
                            println!("do we get here? kind/create/0");
                            let new_wd = unsafe {
                                libc::inotify_add_watch(
                                    watch_fd,
                                    this_event_name_cstr,
                                    IN_WATCH_OPT,
                                )
                            };
                            println!(
                                "do we get here? kind/create/1 / path_string : {} / new_wd : {}",
                                path_string, new_wd
                            );
                            pm.insert(new_wd, path_string);
                        } else if kind == Kind::Dir && what == What::Destroy {
                            println!("do we get here? kind/destroy/0");
                            unsafe { libc::inotify_rm_watch(watch_fd, this_event.wd) };
                            println!("do we get here? kind/destroy/1");
                            let v = pm.remove(&this_event.wd);
                            if let Some(v) = v {
                                println!("have some v : {}", v);
                            }
                            println!("do we get here? kind/destroy/2 / wd : {}", this_event.wd);
                        }
                    } else {
                        println!("e/self/overflow : {}", strerrno());
                    }

                    println!("do we get here? next_ptr/0");
                    let next_event_ptr = unsafe { this_event_ptr.add(1) };
                    this_event_ptr = next_event_ptr;
                    println!("do we get here? next_ptr/1");

                    // println!("next_event_ptr : {}", next_event_ptr as usize);
                }
                true
            }

            EventRecvState::Error => {
                println!("error : {}", strerrno());
                false
            }

            EventRecvState::Eventless => true,
        };
    }
    true
}

fn strerrno() -> String {
    let errno = unsafe { *libc::__errno_location() };
    unsafe { core::ffi::CStr::from_ptr(libc::strerror(errno)) }
        .to_string_lossy()
        .into_owned()
}

pub fn watch(path: String, event_tx: SyncSender<Event>, ctl_rx: SyncReceiver<bool>) -> bool {
    use std::sync::mpsc::TryRecvError::Empty;
    const EVENT_WAIT_QUEUE_MAX: i32 = 1;

    let is_living = || match ctl_rx.try_recv() {
        Err(Empty) => true,
        Ok(false) => false,
        Ok(true) => true,
        Err(_) => false,
    };

    let pb = std::path::PathBuf::from(path);
    let sr = system_unfold();
    let mut pm = path_map(&pb, sr.watch_fd);
    let mut event_recv_list =
        [libc::epoll_event { events: 0, u64: 0 }; EVENT_WAIT_QUEUE_MAX as usize];
    let event_recv_list_ptr = event_recv_list.as_mut_ptr() as *mut libc::epoll_event;

    if sr.valid {
        if pm.len() > 0 {
            while is_living() {
                let event_count = unsafe {
                    libc::epoll_wait(sr.event_fd, event_recv_list_ptr, EVENT_WAIT_QUEUE_MAX, 16)
                };

                if event_count < 0 {
                    system_fold(sr);
                    println!("e/sys/epoll_wait : {}", strerrno());
                    return false;
                } else if event_count > 0 {
                    for n in 0..event_count {
                        let this_event_fd = event_recv_list.index(n as usize).u64;

                        if this_event_fd == sr.watch_fd as u64 {
                            if !do_event_recv(sr.watch_fd, &mut pm, event_tx.clone()) {
                                system_fold(sr);
                                println!("e/self/event_recv : {}", strerrno());
                                return false;
                            }
                        }
                    }
                }
            }
            system_fold(sr)
        } else {
            system_fold(sr);
            println!("e/self/path_map : {}", strerrno());
            return false;
        }
    } else {
        system_fold(sr);
        println!("e/self/sys_resource : {}", strerrno());
        return false;
    }
}

fn main() {
    let (ctl_tx, ctl_rx) = std::sync::mpsc::channel::<bool>();
    let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();
    let path: String = ".".to_string();

    watch(path, event_tx, ctl_rx);
}
