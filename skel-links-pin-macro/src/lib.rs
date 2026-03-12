use proc_macro::TokenStream;
use quote::quote;
use std::fs;
use std::path::PathBuf;
use syn::parse::{Parse, ParseStream};
use syn::{
    Expr, Fields, GenericArgument, Ident, Item, PathArguments, Token, Type, parse_macro_input,
};

struct PinSkelLinksInput {
    links_struct: Ident,
    links_expr: Expr,
    pin_dir_expr: Expr,
}

impl Parse for PinSkelLinksInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let links_struct = input.parse()?;
        input.parse::<Token![,]>()?;
        let links_expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let pin_dir_expr = input.parse()?;

        Ok(Self {
            links_struct,
            links_expr,
            pin_dir_expr,
        })
    }
}

#[proc_macro]
pub fn pin_skel_links(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as PinSkelLinksInput);

    match expand_pin_skel_links(input) {
        Ok(tokens) => tokens,
        Err(err) => err.to_compile_error(),
    }
    .into()
}

fn expand_pin_skel_links(input: PinSkelLinksInput) -> syn::Result<proc_macro2::TokenStream> {
    let skel_source = load_skeleton_source()?;
    let parsed_file = syn::parse_file(&skel_source)?;
    let link_fields = extract_link_fields(&parsed_file, &input.links_struct)?;

    if link_fields.is_empty() {
        return Err(syn::Error::new(
            input.links_struct.span(),
            format!(
                "`{}` does not declare any named link fields",
                input.links_struct
            ),
        ));
    }

    let links_expr = input.links_expr;
    let pin_dir_expr = input.pin_dir_expr;

    Ok(quote! {{
        let __links = &mut (#links_expr);
        let __pin_dir = ::std::path::Path::new(&(#pin_dir_expr));

        #(
            {
                let __pin_path = __pin_dir.join(::core::stringify!(#link_fields));
                let __link = __links
                    .#link_fields
                    .as_mut()
                    .ok_or_else(|| {
                        ::std::io::Error::new(
                            ::std::io::ErrorKind::NotFound,
                            format!(
                                "eBPF link `{}` is not attached and cannot be pinned",
                                ::core::stringify!(#link_fields),
                            ),
                        )
                    })?;

                __link.pin(&__pin_path)?;

                ::log::info!(
                    "Pinned eBPF program `{}` to {}",
                    ::core::stringify!(#link_fields),
                    __pin_path.display()
                );
            }
        )*
    }})
}

fn load_skeleton_source() -> syn::Result<String> {
    let skel_path = std::env::var("LIBBPF_RS_SKEL_PATH").map_err(|_| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            "LIBBPF_RS_SKEL_PATH is not set; build.rs must export the generated skeleton path",
        )
    })?;

    let skel_path = PathBuf::from(skel_path);
    fs::read_to_string(&skel_path).map_err(|err| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "failed to read generated skeleton at {}: {}",
                skel_path.display(),
                err
            ),
        )
    })
}

fn extract_link_fields(file: &syn::File, links_struct: &Ident) -> syn::Result<Vec<Ident>> {
    let Some(item_struct) = find_struct(&file.items, links_struct) else {
        return Err(syn::Error::new(
            links_struct.span(),
            format!(
                "could not find `{}` in the generated skeleton",
                links_struct
            ),
        ));
    };

    let Fields::Named(fields) = &item_struct.fields else {
        return Err(syn::Error::new(
            item_struct.ident.span(),
            format!("`{}` must be a struct with named fields", item_struct.ident),
        ));
    };

    Ok(fields
        .named
        .iter()
        .filter(|field| is_option_link(&field.ty))
        .filter_map(|field| field.ident.clone())
        .collect())
}

fn find_struct<'a>(items: &'a [Item], links_struct: &Ident) -> Option<&'a syn::ItemStruct> {
    items.iter().find_map(|item| match item {
        Item::Struct(item_struct) if item_struct.ident == *links_struct => Some(item_struct),
        Item::Mod(item_mod) => item_mod
            .content
            .as_ref()
            .and_then(|(_, items)| find_struct(items, links_struct)),
        _ => None,
    })
}

fn is_option_link(ty: &Type) -> bool {
    let Type::Path(type_path) = ty else {
        return false;
    };

    let Some(option_segment) = type_path.path.segments.last() else {
        return false;
    };

    if option_segment.ident != "Option" {
        return false;
    }

    let PathArguments::AngleBracketed(arguments) = &option_segment.arguments else {
        return false;
    };

    let Some(GenericArgument::Type(Type::Path(inner_type))) = arguments.args.first() else {
        return false;
    };

    inner_type
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Link")
}
