use crate::x64::tests::{module::Module, utils::hex_dump};

#[test]
fn test_module_load_read_memory() {
    let path = r"src\x64\tests\collateral\x64.dll";
    let module = Module::load(path);
    assert!(module.is_ok());

    let module = module.unwrap();
    let memory = module.read_memory();
    hex_dump(memory.as_ptr(), 40);
    module.unload();
}
