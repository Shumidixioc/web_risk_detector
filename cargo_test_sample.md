

$ cd web_risk_detector

$ ls
Cargo.lock  cargo_run_sample.md   detector/    knowledgebase/  README.md
Cargo.toml  cargo_test_sample.md  javascript/  LICENSE         target/

$ cargo test
    Finished test [unoptimized + debuginfo] target(s) in 0.05s
     Running unittests src\main.rs (target\debug\deps\detector-e278eef9aae85619.exe)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src\lib.rs (target\debug\deps\javascript-04045527e9cb2360.exe)

running 12 tests
test tests::check_if_anonymous_function_test ... ok
test tests::check_if_fun_test ... ok
test tests::check_if_hex_name_test ... ok
test tests::check_if_it_use_eval_test ... ok
test tests::check_if_it_use_exec_script_test ... ok
test tests::check_if_it_use_fetch_test ... ok
test tests::check_if_it_prevent_default_test ... ok
test tests::check_if_it_use_local_storage_test ... ok
test tests::check_if_it_use_xml_http_req_test ... ok
test tests::check_if_line_size_is_too_big_test ... ok
test tests::check_if_var_test ... ok
test tests::it_works ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s


   Doc-tests javascript

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


$
