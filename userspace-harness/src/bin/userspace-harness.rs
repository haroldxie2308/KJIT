use userspace_harness::{cases, run_case};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--list") {
        for case in cases::built_in_cases() {
            println!("{}\t{}", case.name, case.description);
        }
        return;
    }

    let selected = if args.is_empty() {
        cases::built_in_cases()
    } else {
        let mut selected = Vec::new();
        for name in args {
            match cases::find_case(&name) {
                Some(case) => selected.push(case),
                None => {
                    eprintln!("unknown case: {name}");
                    std::process::exit(2);
                }
            }
        }
        selected
    };

    let mut failed = false;
    for case in selected {
        match run_case(&case) {
            Ok(report) => {
                println!(
                    "PASS {}\toriginal/lowered/encoded states match\tencoded_bytes={}",
                    report.name,
                    report.encoded_program.len()
                );
            }
            Err(err) => {
                failed = true;
                eprintln!("FAIL {}\n{}", case.name, err);
            }
        }
    }

    if failed {
        std::process::exit(1);
    }
}
