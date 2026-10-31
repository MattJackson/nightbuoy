// Windows packages pair the windowed launcher (.exe) with the console build (.com).
#![cfg_attr(windows, windows_subsystem = "windows")]
include!("main.rs");
