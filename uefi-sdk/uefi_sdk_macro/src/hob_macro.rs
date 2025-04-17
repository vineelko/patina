use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse::Parse, spanned::Spanned, Attribute, Generics, ItemEnum, ItemStruct, Meta};

struct AttrConfig {
    hob_guid: TokenStream,
}

struct HobConfig {
    item: ItemStruct,
    config: AttrConfig,
}

impl HobConfig {
    fn parse_attr(attrs: &mut Vec<Attribute>) -> syn::Result<AttrConfig> {
        let mut config = AttrConfig { hob_guid: TokenStream::new() };
        for attr in attrs {
            if attr.path().is_ident("hob") {
                config.hob_guid = Self::parse_hob_attr(attr)?;
            }
        }

        Ok(config)
    }

    fn parse_hob_attr(attr: &Attribute) -> syn::Result<TokenStream> {
        let Meta::NameValue(nv) = &attr.meta else {
            return Err(syn::Error::new(attr.span(), "Expected #[hob = \"GUID\"]"));
        };

        let id = match uuid::Uuid::parse_str(&nv.value.to_token_stream().to_string().replace("\"", "")) {
            Err(_) => return Err(syn::Error::new(attr.span(), "Invalid GUID format")),
            Ok(id) => id,
        };

        let bytes = id.as_fields();
        let (a, b, c, [d0, d1, d2, d3, d4, d5, d6, d7]) = bytes;

        Ok(quote! {
            uefi_sdk::component::service::Guid::from_fields(#a, #b, #c, #d0, #d1, &[#d2, #d3, #d4, #d5, #d6, #d7])
        })
    }

    /// Returns the name [Ident](syn::Ident) of the struct
    fn ident(&self) -> &syn::Ident {
        &self.item.ident
    }

    /// Returns the parsed attribute configuration.
    fn config(&self) -> &AttrConfig {
        &self.config
    }

    /// The generics for the struct
    fn generics(&self) -> Generics {
        self.item.generics.clone()
    }

    /// The left hand side generics for the struct, which can include trait bounds.
    fn lhs_generics(&self) -> Generics {
        self.generics()
    }

    /// The right hand side generics for the struct, which do not include trait bounds.
    ///
    /// valid: `impl<T: Debug> SomeTrait for MyStruct<T> {}`
    /// invalid: `impl SomeTrait for MyStruct<T: Debug> {}`
    fn rhs_generics(&self) -> Generics {
        let mut generics = self.generics();
        for param in generics.params.iter_mut() {
            if let syn::GenericParam::Type(param) = param {
                param.bounds.clear();
            }
        }
        generics.where_clause = None;
        generics
    }
}

impl TryFrom<ItemStruct> for HobConfig {
    type Error = syn::Error;

    fn try_from(mut item: ItemStruct) -> syn::Result<Self> {
        let config = Self::parse_attr(&mut item.attrs)?;
        if config.hob_guid.is_empty() {
            return Err(syn::Error::new(
                item.span(),
                "Missing required attribute `#[hob = \"GUID\"]` for HobConfig derive macro.",
            ));
        }
        Ok(HobConfig { item, config })
    }
}

impl Parse for HobConfig {
    fn parse(stream: syn::parse::ParseStream) -> syn::Result<Self> {
        if stream.fork().parse::<ItemStruct>().is_ok() {
            Ok(stream.parse::<ItemStruct>().and_then(HobConfig::try_from)?)
        } else if stream.fork().parse::<ItemEnum>().is_ok() {
            Err(syn::Error::new(stream.span(), "Enum types are not currently supported."))
        } else {
            Err(syn::Error::new(stream.span(), "Union types are not currently supported."))
        }
    }
}

pub fn hob_config2(item: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    let config = match syn::parse2::<HobConfig>(item) {
        Ok(config) => config,
        Err(err) => return err.to_compile_error(),
    };

    let name = config.ident();
    let lhs = config.lhs_generics();
    let rhs = config.rhs_generics();
    let where_clause = config.generics().where_clause;
    let hob_guid = &config.config().hob_guid;

    quote! {
        impl #lhs uefi_sdk::component::hob::FromHob for #name #rhs #where_clause {
            const HOB_GUID: uefi_sdk::component::service::Guid = #hob_guid;

            fn parse(bytes: &[u8]) -> Self {
                assert!(
                    bytes.len() >= core::mem::size_of::<Self>(),
                    "Guided Hob [{:#?}] parse failed. Buffer to small for type {}", Self::HOB_GUID, core::any::type_name::<Self>()
                );
                unsafe { *(bytes.as_ptr() as *const Self) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proc_macro2::TokenStream;
    use quote::quote;

    #[test]
    fn test_config_basic() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            #[hob = "8be4df61-93ca-11d2-aa0d-00e098032b8c"]
            struct MyStruct(u32);
        };
        let expected = quote! {
            impl uefi_sdk::component::hob::FromHob for MyStruct {
                const HOB_GUID: uefi_sdk::component::service::Guid = uefi_sdk::component::service::Guid::from_fields(2347032417u32, 37834u16, 4562u16, 170u8, 13u8, &[0u8, 224u8, 152u8, 3u8, 43u8, 140u8]);
                fn parse(bytes: &[u8]) -> Self {
                    assert!(
                        bytes.len() >= core::mem::size_of::<Self>(),
                        "Guided Hob [{:#?}] parse failed. Buffer to small for type {}", Self::HOB_GUID, core::any::type_name::<Self>()
                    );
                    unsafe { *(bytes.as_ptr() as *const Self) }
                }
            }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_config_with_generics() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            #[hob = "8be4df61-93ca-11d2-aa0d-00e098032b8c"]
            struct MyStruct<T>(u32, T);
        };
        let expected = quote! {
            impl<T> uefi_sdk::component::hob::FromHob for MyStruct<T> {
                const HOB_GUID: uefi_sdk::component::service::Guid = uefi_sdk::component::service::Guid::from_fields(2347032417u32, 37834u16, 4562u16, 170u8, 13u8, &[0u8, 224u8, 152u8, 3u8, 43u8, 140u8]);
                fn parse(bytes: &[u8]) -> Self {
                    assert!(
                        bytes.len() >= core::mem::size_of::<Self>(),
                        "Guided Hob [{:#?}] parse failed. Buffer to small for type {}", Self::HOB_GUID, core::any::type_name::<Self>()
                    );
                    unsafe { *(bytes.as_ptr() as *const Self) }
                }
            }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_config_with_missing_hob() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            struct MyStruct(u32);
        };
        let expected = quote! {
            :: core :: compile_error ! { "Missing required attribute `#[hob = \"GUID\"]` for HobConfig derive macro." }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_config_with_bad_hob() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            #[hob = "invalid-guid"]
            struct MyStruct(u32);
        };
        let expected = quote! {
            :: core :: compile_error ! { "Invalid GUID format" }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_bad_hob_attr_usage() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            #[hob("8be4df61-93ca-11d2-aa0d-00e098032b8c")]
            struct MyStruct(u32);
        };
        let expected = quote! {
            :: core :: compile_error ! { "Expected #[hob = \"GUID\"]" }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_on_enum_type() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            #[hob = "8be4df61-93ca-11d2-aa0d-00e098032b8c"]
            enum MyEnum {
                Variant1,
                Variant2,
            }
        };
        let expected = quote! {
            :: core :: compile_error ! { "Enum types are not currently supported." }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_on_union_type() {
        let input: TokenStream = quote! {
            #[derive(HobConfig)]
            #[hob = "8be4df61-93ca-11d2-aa0d-00e098032b8c"]
            union MyUnion {
                field1: u32,
                field2: u32,
            }
        };
        let expected = quote! {
            :: core :: compile_error ! { "Union types are not currently supported." }
        };

        let output = hob_config2(input);
        assert_eq!(output.to_string(), expected.to_string());
    }
}
