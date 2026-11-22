//! Execution only: no prover, network SDK or credential discovery.
use zkm_core_executor::{ExecutionError, Executor, Program};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(
        args.len(),
        3,
        "usage: trusted-shim-guest-check ELF INPUT EXPECTED_OUTPUT|reject"
    );
    let elf = std::fs::read(&args[0]).expect("read ELF");
    let input = std::fs::read(&args[1]).expect("read input");
    let mut executor = Executor::new(Program::from(&elf).expect("MIPS ELF"), Default::default());
    executor.max_cycles = Some(1_000_000_000);
    executor.state.input_stream.push(input);
    let result = executor.run_fast();
    if args[2] == "reject" {
        assert!(
            matches!(result, Err(ExecutionError::HaltWithNonZeroExitCode(1))),
            "expected rejection: {result:?}"
        );
        assert!(
            executor.state.public_values_stream.is_empty(),
            "rejected guest committed output"
        );
    } else {
        result.expect("guest execution");
        assert_eq!(
            executor.state.public_values_stream,
            std::fs::read(&args[2]).expect("read expected output")
        );
    }
    println!("MIPS agreement: {} cycles", executor.state.global_clk);
}
