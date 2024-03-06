use ferrisetw::native::ExtendedDataItem;
use ferrisetw::parser::Parser;
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use windows_sys::Win32::System::{
    Diagnostics::Etw::EVENT_HEADER_EXT_TYPE_STACK_TRACE64, Threading::PROCESS_DUP_HANDLE,
};

const LOGMAN: &str = r"C:\Windows\System32\logman.exe";
const TRACE_NAME: &str = "MyAuditAPICallsTracer";
// Microsoft-Windows-Kernel-Audit-API-Calls
const AUDIT_API_CALLS_GUID: &str = "e02a841c-75a3-4fa7-afc8-ae09cf9b7f23";
const AUDIT_API_CALLS_OPENPROCESS: u16 = 5;

fn main() {
    env_logger::init();

    let wait_for_ctrl_c = utils::WaitForCtrlC::try_new().expect("Error setting Ctrl-C handler.");
    println!(
        "This tool catches failures to open a process for handle duplication (and only that)."
    );
    println!("(Press Ctrl-C to stop.)");

    // Stop the trace from a previous instance if it is still running
    utils::run_command(LOGMAN, &["stop", "-ets", TRACE_NAME]).expect("Error running logman.");

    let user_trace = spawn_tracing_thread();
    wait_for_ctrl_c.wait();
    drop(user_trace);
}

fn spawn_tracing_thread() -> UserTrace {
    let audit_api_calls_provider = Provider::by_guid(AUDIT_API_CALLS_GUID)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE)
        .add_callback(on_api_call_provider_event)
        .build();

    let (user_trace, handle) = UserTrace::new()
        .named(String::from(TRACE_NAME))
        .enable(audit_api_calls_provider)
        .start()
        .unwrap();

    std::thread::spawn(move || {
        let status = UserTrace::process_from_handle(handle);
        println!("Trace ended with status {:?}.", status);
    });

    user_trace
}

fn on_api_call_provider_event(record: &EventRecord, schema_locator: &SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            let extended_data = record.extended_data();
            let event_id = record.event_id();
            if event_id == AUDIT_API_CALLS_OPENPROCESS {
                let parser = Parser::create(record, &schema);
                let return_code: u32 = parser.try_parse("ReturnCode").unwrap();
                let desired_access: u32 = parser.try_parse("DesiredAccess").unwrap();
                if desired_access == PROCESS_DUP_HANDLE && return_code != 0 {
                    let process_id = record.process_id();
                    let thread_id = record.thread_id();
                    let target_process_id: u32 = parser.try_parse("TargetProcessId").unwrap();
                    println!(
                        "In process {process_id} thread {thread_id}: OpenProcess(target_pid={target_process_id}, desired_access={desired_access}) failed with NTSTATUS 0x{return_code:08x}. Call stack:",
                    );
                    for item in extended_data {
                        if item.data_type() as u32 == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 {
                            if let ExtendedDataItem::StackTrace64(stack_trace) =
                                item.to_extended_data_item()
                            {
                                for (i, address) in stack_trace.addresses().iter().enumerate() {
                                    println!("[{i:02x}]: {address:016x}");
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(err) => println!("Error {:?}.", err),
    }
}

mod utils {
    use std::process::Command;
    use std::process::Output;
    use std::sync::Arc;
    use std::sync::Condvar;
    use std::sync::Mutex;

    pub(crate) fn run_command(program: &str, args: &[&str]) -> std::io::Result<Output> {
        Command::new(program).args(args).output()
    }

    pub(crate) struct WaitForCtrlC {
        pair: Arc<(Mutex<bool>, Condvar)>,
    }

    impl WaitForCtrlC {
        pub(crate) fn try_new() -> Result<WaitForCtrlC, ctrlc::Error> {
            let pair = Arc::new((Mutex::new(true), Condvar::new()));
            let pair_clone = Arc::clone(&pair);

            ctrlc::set_handler(move || {
                let (lock, cvar) = &*pair_clone;
                let mut running = lock.lock().unwrap();
                *running = false;
                cvar.notify_one();
            })
            .map(|_| WaitForCtrlC { pair })
        }

        pub(crate) fn wait(&self) {
            let (lock, cvar) = &*self.pair;
            let mut running = lock.lock().unwrap();
            while *running {
                running = cvar.wait(running).unwrap();
            }
        }
    }

    impl Drop for WaitForCtrlC {
        fn drop(&mut self) {
            let (lock, _cvar) = &*self.pair;
            let running = *lock.lock().unwrap();
            assert!(!running);
        }
    }
}
