/// A very simple profiling tool.
///
/// Note: don't ever profile code that has not been compiled in
/// release mode.  There can be orders of magnitude difference in
/// execution time between it and debug mode!
///
/// This macro measures the wall time it takes to execute the block.
/// If the time is at least $ms_threshold (in milli-seconds), then it
/// displays the output on stderr.  The output is prefixed with label,
/// if it is provided.
///
/// ```nocompile
/// let result = time_it!("Some code", 10, {
///     // Some code.
///     5
/// });
/// assert_eq!(result, 5);
/// ```
#[allow(unused_macros)]
macro_rules! time_it {
    ( $label:expr, $ms_threshold:expr, $body:expr ) => {{
        use std::time::{SystemTime, Duration};

        // We use drop so that code that uses non-local exits (e.g.,
        // using break 'label) still works.
        struct Timer {
            start: SystemTime,
        }
        impl Drop for Timer {
            fn drop(&mut self) {
                let elapsed = self.start.elapsed();
                if elapsed.clone().unwrap_or(Duration::from_millis($ms_threshold))
                    >= Duration::from_millis($ms_threshold)
                {
                    if $label.len() > 0 {
                        eprint!("{}:", $label);
                    }
                    eprintln!("{}:{}: {:?}", file!(), line!(), elapsed);
                }
            }
        }

        let _start = Timer { start: SystemTime::now() };
        $body
    }};
    ( $label:expr, $body:expr ) => {
        time_it!($label, 0, $body)
    };
    ( $body:expr ) => {
        time_it!("", $body)
    };
}
