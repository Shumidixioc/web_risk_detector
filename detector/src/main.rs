/*
    Binary crate detector.
    Detections/Security
    main.rs
*/


use std::fs;
use javascript;

pub fn info_x(file_name: &str)->(usize, Vec<javascript::JavaScriptModel>, javascript::StatsModel, javascript::StatsListModel) {
    //
    let contents = fs::read_to_string(file_name).unwrap();
    let script_size = contents.len();
    let last_char = contents.chars().nth(script_size - 1);
    let lines: Vec<&str> = contents.split(';').collect();
    let mut javascript_lines: Vec<javascript::JavaScriptModel> = Vec::new();
    let mut line_number: usize = 0;
    let lines_len = lines.len();
    //
    let mut stats = javascript::StatsModel {
        var: 0, function: 0, let_kw: 0, const_kw: 0,
        anonymous_function: 0,
        fetch: 0, xml_http_request: 0, eval: 0,
        exec_script: 0, prevent_default: 0,
        local_storage: 0, atob: 0, btoa: 0,
        unusual_behavior: 0,
        suspicious_behavior: 0,
        flags: 0,
        // lambda_statements: 0,
    };
    //
    let mut stats_list = javascript::StatsListModel {
        var_names: Vec::new(), function_names: Vec::new(),
        const_names: Vec::new(), other_names: Vec::new(),
        flag_reasons: Vec::new(),
    };
    //
    for line in lines {
        line_number += 1;
        let mut line_x = String::from(line);
        if (line_number < lines_len) | (last_char == Some(';')) {
           line_x.push(';');
        }
        let javascript_x = javascript::new(line_number, line_x, script_size, &mut stats, &mut stats_list);
        javascript_lines.push(javascript_x);
    }
    //
    (script_size, javascript_lines, stats, stats_list)

}

fn info() {
    //
    // let file_name01 = "knowledgebase\\file1.js";
    // let file_name02 = "knowledgebase\\file2.js";
    // let file_name03 = "knowledgebase\\file3.js";
    let file_name04 = "knowledgebase\\file4.js";
    //
    println!("// -------------------------------------------");
    let info_js = info_x(file_name04);
    println!("file_name: {:#?}, info: {:#?}",file_name04,  info_js);
    println!("// -------------------------------------------");
    //

}

fn info_all() {
    let file_name01 = "knowledgebase\\file1.js";
    let file_name02 = "knowledgebase\\file2.js";
    let file_name03 = "knowledgebase\\file3.js";
    // let file_name04 = "knowledgebase\\file4.js";
    //
    println!("// -------------------------------------------");
    let mut info_js = info_x(file_name01);
    println!("file_name: {:#?}, info: {:#?}",file_name01,  info_js);
    //
    println!("// -------------------------------------------");
    info_js = info_x(file_name02);
    println!("file_name: {:#?}, info: {:#?}",file_name02,  info_js);
    //
    println!("// -------------------------------------------");
    info_js = info_x(file_name03);
    println!("file_name: {:#?}, info: {:#?}",file_name03,  info_js);
    //
    println!("// -------------------------------------------");
    // info_js = info_x(file_name04);
    // println!("file_name: {:#?}, info: {:#?}",file_name04,  info_js);
    // println!("// -------------------------------------------");

}

fn main() {
    println!("Hello, world!");
    info_all();
    info();
}
