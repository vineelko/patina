//! A crate containing macros to be re-exported in the `uefi_sdk` crate.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
mod component_macro;
mod service_macro;

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
#[proc_macro_derive(IntoComponent, attributes(entry_point, protocol))]
pub fn component(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    component_macro::component2(item.into()).into()
}

/// Derive Macro for implementing the `IntoService` trait for a type.
///
/// This macro automatically implements the necessary traits for the provided type implementation to be used as a
/// `Service`. By default the derive macro assumes the service is the same as the deriver, but that can be overridden
/// with the `service` attribute to specify that the service is actually a dyn \<Trait\> that the underlying type
/// implements.
///
/// ## Macro Attribute
///
/// - `service`: The service trait(s) that the type implements.
/// - `protocol`: Publishes the entire struct as a protocol with the given GUID.
///
/// ## Member Attributes
///
/// - `protocol`: Publishes the field as a protocol with the given GUID.
///
/// ## Pure Rust Example
///
/// ```rust, ignore
/// use uefi_sdk::{
///    error::Result,
///    component::{
///      IntoService,
///      params::Service,
///    },
/// };
///
/// trait MyService {
///   fn do_something(&self) -> Result<()>;
/// }
///
/// #[derive(IntoService)]
/// #[service(MyService)]
/// struct MyStruct;
///
/// impl MyService for MyStruct {
///   fn do_something(&self) -> Result<()> {
///    Ok(())
///   }
/// }
/// ```
///
/// ## Pure Protocol Example
///
/// ```rust, ignore
/// #[derive(IntoService)]
/// #[protocol = "8be4df61-93ca-11d2-aa0d-00e098032b8c"]
/// struct MyStruct {
///   f: extern "efiapi" fn() -> r_efi::efi::Status;
/// }
/// ```
#[proc_macro_derive(IntoService, attributes(protocol, service))]
pub fn service(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    service_macro::service2(item.into()).into()
}
