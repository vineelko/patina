# Getting Started

A crate for code needed in core modules used in UEFI firmware.

## Commands

Read Everything below already? If not, read the below first. This is just better to have at the top

- `cargo make build-std` Builds all crates with the std feature, including any std binary drivers.
- `cargo make build-x64` Builds all* crates with the x64 feature, including any uefi drivers.
- `cargo make build-aarch64` Builds all* crates with the aarch64 feature, including any uefi drivers.
- `cargo make test` Runs all unit tests.

\* Does not build `mu_config` or `mu_macro` as these crates are build-time dependencies that only support the std
environment.

## Actually Getting Started

This repository provides a design for building components and libraries in a decoupled way to allow for "hot swapping"
of libraries when compiling a component. This is accomplished by defining a component as a struct that describes the
library abstractions it needs using the rust feature of traits:

```rust
pub struct HelloWorldComponent<E>
where
    E: ExampleLib // Library Interface the component needs
{
    _e: PhantomData<DE>
}
```

From there, the `Component` trait is implemented on the struct, which is where the core logic of
the component is located. Accessing library functionality is as easy as calling their static
methods as described by the trait interface:

```rust
impl <E>Component for HelloWorldComponent<E>
where
    E: ExampleLib
{
    fn entry_point() -> Result<()> {
        E::my_function();
        Ok(())
    }

    ...
}
```

As alluded to in the previous sentence, a library interface is simply a rust trait that the
instances will implement, ensuring the expected function interfaces exist, and allowing the
component to statically abstract away which library is used, until it is time to instantiate the
specific instance of the component (i.e. the specific libraries the component uses). This allows
the component to swap libraries instances without any coupling. Libraries can even have additional
library dependencies of their own!

```rust
struct MyExampleLib;
impl ExampleLib on MyExampleLib {
    fn my_function() {
        // Do Nothing
    }
}

struct MyExampleLib2<P: PortLib>;
impl <P> on MyExampleLib2<P>
where
    P: PortLib
{
    fn my_function() {
        ...
    }
}
```

The final step is to instantiate the component, selecting the library implementations it will
use. To do so, simply create a type alias for the driver and it's selected drivers, then call
the entry point:

```rust
type Driver = HelloWorldComponent<MyDebugLib>;
```

By using these abstractions, it is actually possible to swap libraries for `std` supported
instances, and run your component on the host machine!

## Complex dependencies and Easily exchanging library instances

While the above example was simple and easy, real world components have much more complex library dependencies! If you
have every build a dependency tree of a EDKII component, you will see that a low amount of top level dependencies can
still result in a huge about of overall dependencies! Lets say your component has 2 dependencies, and those two also
have two, and so on and so on... well you can do the math - 2^x can be a lot!

One weakness of this architecture is that due to the complexity described above, creating the type alias can be
incredibly complex, and changing even a single library could be an effort. Lets take the following example:

- Component: MyComponent with library dependencies on MyLib1 and MyLib2
- MyLib1 - MyLib1Impl with dependency on MyLib2 and MyLib3
- MyLib2 - MyLib2Impl with a dependency on MyLib4
- MyLib3 - MyLib3Impl
- MyLib4 - MyLib4Impl

A driver type alias for this would look like:

```rust
type Driver = MyComponent< MyLib1Impl< MyLib2Impl< MyLib4Impl >, MyLib3Impl >, MyLib2< MyLib4Impl > >;
```

Don't worry, you don't need to fully get the above, heck I struggled to make sure I wrote it correctly! And that was a
fairly simple example. In this example, lets say I wanted to swap MyLib2Impl to MyLib2ImplExtra, I now have to switch
both occurrences of MyLib2Impl to MyLib2Extra,which will cascade down to the dependencies of MyLib2Impl. It would be a
lot of work!

Because this is complex, we created a macro that does it for you! All that needs to be done is to write the component,
and each library instance once, and the macro will take care of replacing libraries with their library instances:

```rust
type Driver = component!(MyComponent<MyLib1, MyLib2>;
    MyLib1 = MyLib1Impl<MyLib2, MyLib3>;
    MyLib2 = MyLib2Impl<MyLib4>;
    MyLib3 = MyLib3Impl;
    MyLib4 = MyLib4Impl;
);
```

While this is slightly longer than doing it manually, it is much easier to (1) understand and (2) change library
instances. Additionally, we are still working on relatively simple examples. The more complex it is, the more useful
this macro is. Here is the above driver, but with Lib1 swapped:

```rust
type Driver = component!(MyComponent<MyLib1, MyLib2>;
    MyLib1 = MyLib1Impl2<MyLib3>;
    MyLib2 = MyLib2Impl<MyLib4>;
    MyLib3 = MyLib3Impl;
    MyLib4 = MyLib4Impl;
);
```

With a simple change, we cascaded a change in the type alias:

```rust
type Driver = MyComponent< MyLib1Impl< MyLib2Impl< MyLib4Impl >, MyLib3Impl >, MyLib2< MyLib4Impl > >;
type Driver = MyComponent< MyLib1Impl2< MyLib3Impl >, MyLib2< MyLib4Impl > >;
```

## Configuring components through External Config files

Similar to how EDKII relies on a DSC to specify library usage, we too need a way to easily swap dependencies across all
components. With what you've seen so far, if you wanted to swap MyLib1 from MyLib1Impl to MyLib1Impl2, you would need
to go into each component's type definition and update it. This is not very productive. So we've added a way to allow
generic configurations across multiple components using a config file similar to a dsc. We've implemented it very
simply, using the `toml` format.

Instead of passing library instances inside the `component!` macro, you can instead use the `component_from_path!` macro
that accepts either the `path` or `env` keyword that allows you to directly set the config file (with `Path`) or allow
the build system to find the config file whose path is determined by an environment variable (with `Env`).

```rust
type Driver = component_from_path!(MyComponent<MyLib1, MyLib2>; Path="/Path/To/Config.toml")
type Driver = component_from_path!(MyComponent<MyLib1, MyLib2>; Env="ENV_VAR_WITH_PATH_TO_CONFIG")
```

We will then use that configuration file to select the appropriate library instances - similar to the DSC. Here is an
example Configuration file. It is a simple `<library_name> = <include_path>`:

``` toml
[libraryinstances]
MyLib1 = "pkg1::library::MyLib1Impl<MyLib3>"
MyLib2 = "pkg2::library::MyLib2Impl<MyLib4>"
MyLib3 = "pkg1::library::MyLib3Impl"
MyLib4 = "pkg3::library::MyLib4Impl"
```

being as this is a toml config file, there are plenty of possibilities to add additional configuration possibilities to
help mirror the functionality of DSCs. You can also note that since there really is no equivalent to an INF, we need to
describe each library's library dependencies directly in this file.

## Crates

Below are the list of crates and their purpose / contents.

### uefi_core

This crate provides the trait definition for a Component, and a error enum for converting between
the typical rust error handling (with "?"s) and UEFI error handling (returning EFI_X)

### uefi_cpu_init

This crate provides cpu architecture-specific functionality like managing the GDT and IDT on x86 platforms.

### uefi_logger

This crate provides debugging support code. For example, to support writing to serial or a memory buffer.

### mu_macro

This crate provides the component!() macro for generating the type definition for a component.

### mu_config

This crate provides an interface for parsing the config file for specifying dependencies.
