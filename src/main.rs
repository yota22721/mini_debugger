use std::collections::{HashMap};
use std::result::Result;
use std::os::unix::process::CommandExt;
use std::process::{Command, exit};
use std::{env};
use libc::c_void;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus};
use nix::sys::ptrace;
use nix::unistd::{fork, Pid};
use nix::sys::wait::waitpid;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
extern crate linux_personality;
use linux_personality::personality;


struct  DebuggerState{
    pid:Pid,
    breakpoints:HashMap<u64,u64>,
}
impl DebuggerState{
    pub fn new(pid:Pid)->Self{
        Self{
            pid,
            breakpoints:HashMap::new(),
            
        }
    }

    pub fn run(&mut self)->Result<(), Box<dyn std::error::Error>>{
        let mut rl = DefaultEditor::new()?;
        loop{
           let readline = rl.readline("(dbgr) ");
            match readline {
                Ok(line) =>{
                    let parts:Vec<&str> = line.trim().splitn(2, ' ').collect();
                    match parts[0]{
                        "b"=>{
                            
                            let addr = u64::from_str_radix(parts[1], 16)?;
                            match set_breakpoint(self.pid, addr){
                                Ok(o)=>{
                                self.breakpoints.insert(addr, o);
                                println!("Breakpoint set at 0x{:x}",addr);
                                },
                                Err(e)=>{println!("Error : {:?}\nfailed to set breakpoint at {:#x}",e,addr);},
                            };

                        }
                        "d"=>{
                            let addr = u64::from_str_radix(parts[1], 16)?;
                            match self.breakpoints.get(&addr){
                                Some(orig_data)=>{
                                    delete_breakpoint(self.pid, addr, *orig_data);
                                    self.breakpoints.remove(&addr);
                                    println!("Breakpoint removed from {:#x}",addr);
                                }
                                _=>{println!("No breakpoint at 0x{:x}",addr);}

                            }
                        }
                        "c"=>{
                            ptrace::cont(self.pid, None)?;
                            wait_trap(self.pid, &self.breakpoints);
                        }
                        "s"=>{
                            ptrace::step(self.pid, None)?;
                            wait_trap(self.pid, &self.breakpoints);
                        }
                        "regs"=>{
                            print_registers(self.pid);
                        }
                        "q"=>{
                            break;
                        }
                        _=>{
                            println!("Unknown command : {}", line);
                        }
                    }

                }
                Err(ReadlineError::Interrupted) =>{
                    println!("Interrunpted");
                    break;
                }
                Err(ReadlineError::Eof)=>{
                    println!("EOF");
                    break;
                }
                Err(err) =>{
                    println!("Error: {:?}",err);
                    break;
                }
            }

        }
        Ok(())
    }
}

fn print_registers(pid:Pid){
    let regs = ptrace::getregs(pid).unwrap();
    println!("%rax: 0x{:x}",regs.rax);
    println!("%rbx: 0x{:x}",regs.rbx);
    println!("%rcx: 0x{:x}",regs.rcx);
    println!("%rdx: 0x{:x}",regs.rdx);
    println!("%rsi: 0x{:x}",regs.rsi);
    println!("%rdi: 0x{:x}",regs.rdi);
    println!("%rbp: 0x{:x}",regs.rbp);
    println!("%rsp: 0x{:x}",regs.rsp);
    println!("%r8: 0x{:x}",regs.r8);
    println!("%r9: 0x{:x}",regs.r9);
    println!("%r10: 0x{:x}",regs.r10);
    println!("%r11: 0x{:x}",regs.r11);
    println!("%r12: 0x{:x}",regs.r12);
    println!("%r13: 0x{:x}",regs.r13);
    println!("%r14: 0x{:x}",regs.r14);
    println!("%r15: 0x{:x}",regs.r15);
    println!("%rip: 0x{:x}",regs.rip);
    println!("%eflags: 0x{:x}",regs.eflags);
    println!("%cs: 0x{:x}",regs.cs);
    println!("%ss: 0x{:x}",regs.ss);
    println!("%ds: 0x{:x}",regs.ds);
    println!("%es: 0x{:x}",regs.es);
    println!("%fs: 0x{:x}",regs.fs);
    println!("%gs: 0x{:x}",regs.gs);
}

fn set_breakpoint(pid: Pid, addr: u64)->Result<u64, Box<dyn std::error::Error>>{
    let orig_data= ptrace::read(pid, addr as *mut c_void)? as u64;
    let bp = (orig_data &(u64::MAX ^ 0xFF)) | 0xCC;

    unsafe{
        ptrace::write(pid, addr as *mut c_void, bp as *mut c_void)?;
    }

    Ok(orig_data)
}

fn delete_breakpoint(pid: Pid, addr: u64, orig_value: u64){
    unsafe{
        ptrace::write(pid, addr as *mut c_void, orig_value as *mut c_void).unwrap();
    }
}


fn handle_sigstop(pid: Pid, saved_values: &HashMap<u64, u64>){
    let mut regs = ptrace::getregs(pid).unwrap();

    match saved_values.get(&(regs.rip-1)){
        Some(orig) =>{
            delete_breakpoint(pid, regs.rip-1, *orig);

            regs.rip -=1;
            ptrace::setregs(pid, regs).expect("Error rewinding RIP");
        }
        _=>(),
    }
    ptrace::step(pid, None).expect("Restoring breakpoint failed");
}


fn wait_trap(pid: Pid, saved_values: &HashMap<u64, u64>){
    match waitpid(pid, None){
                Ok(status)=>{
                    match status {
                        WaitStatus::Stopped(pid_t, sig)=>{
                            match sig{
                                Signal::SIGTRAP=>{
                                    handle_sigstop(pid_t, &saved_values);
                                }

                                Signal::SIGSEGV=>{
                                    let regs = ptrace::getregs(pid_t).unwrap();
                                    println!("Segmentation fault at 0x{:x}",regs.rip);
                                }
                                _=>{
                                    println!("Some other signal - {}", sig);
                                }
                            }
                        },
                        WaitStatus::Exited(pid, exit_status)=>{
                            println!("Process with pid: {} exited with status {}", pid, exit_status);
                        },
                    _=>{
                        println!("Received status : {:?}",status);
                    }

                    }
                }
                Err(e)=>{
                    println!("Some kind of error - {:?}",e);
                }
            }
}

fn run_elf(fp:&String) {
    ptrace::traceme().unwrap();
    personality(linux_personality::ADDR_NO_RANDOMIZE)
        .expect("[!] cannot set personality");
    Command::new(fp).exec();
    exit(0);

}

fn main() ->Result<(),Box<dyn std::error::Error>> {

    /* Get a elf file */
    let args: Vec<String> = env::args().collect();

    let filepath = match args.get(1){
        Some(f)=>f,
        None =>{
            println!("usage: ./mini_dbg <ELF_FILE_PATH>");
            exit(1);
        }
    };

    /* Detach child process from parent */
    match unsafe {fork()}{
        Ok(nix::unistd::ForkResult::Child)=>{
            run_elf(filepath);
        }
        Ok(nix::unistd::ForkResult::Parent { child })=>{
            let mut state = DebuggerState::new(child);
            state.run()?;
        }
        Err(err)=>{
            panic!("fork failed {}",err);
        }
    }

    Ok(())

}
