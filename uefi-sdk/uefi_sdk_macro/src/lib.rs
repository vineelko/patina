//! A crate containing macros to be re-exported in the `uefi_sdk` crate.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
mod component_macro;

/// Derive Macro for implementing the `IntoComponent` trait for a type.
///
/// This macro automatically implements the necessary traits for the provided type implementation to be used as a
/// `Component`. By default, the component attribute macro will assume a function, `Self::entry_point`, exists on the
/// type, but that can be overridden with the `entry_point` attribute.
///
/// ## Supported types
///
/// - Struct
/// - Enum
///
/// ## Macro Attribute
///
/// - `entry_point`: The function to be called when the component is executed.
///
/// ## Examples
///
/// ```rust, ignore
/// use uefi_sdk::{
///     error::Result,
///     component::{
///         IntoComponent,
///         params::Config,
///     },
/// };
///
/// #[derive(IntoComponent)]
/// struct MyStruct(u32);
///
/// impl MyStruct {
///
///     fn entry_point(self, _cfg: Config<String>) -> Result<()> {
///         Ok(())
///     }
/// }
///
/// #[derive(IntoComponent)]
/// #[entry_point(path = driver)]
/// struct MyStruct2(u32);
///
/// fn driver(s: MyStruct2, _cfg: Config<String>) -> Result<()> {
///    Ok(())
/// }
///
/// #[derive(IntoComponent)]
/// #[entry_point(path = MyEnum::run_me)]
/// enum MyEnum {
///    A,
///    B,
/// }
///
/// impl MyEnum {
///    fn run_me(self, _cfg: Config<String>) -> Result<()> {
///       Ok(())
///   }
/// }
/// ```
#[proc_macro_derive(IntoComponent, attributes(entry_point))]
pub fn component(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    component_macro::component2(item.into()).into()
}
