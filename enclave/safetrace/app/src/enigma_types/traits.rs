//! # Traits module
//! This module should provide low level traits that are required on both sides of the SGX.
//! right now it only contains the [`SliceCPtr`] trait which is used to *always* provide valid C pointers.

static EMPTY: [u8; 1] = [0];

/// This trait provides an interface into `C` like pointers.
/// in Rust if you try to get a pointer to an empty vector you'll get:
/// 0x0000000000000001 OR 0x0000000000000000, although bear in mind this *isn't* officially defined.
/// this behavior is UB in C's `malloc`, passing an invalid pointer with size 0 to `malloc` is implementation defined.
/// in the case of Intel's + GCC what we observed is a Segmentation Fault.
/// this is why if the vec/slice is empty we use this trait to pass a pointer to a stack allocated static `[0]` array.
/// this will make the pointer valid, and when the len is zero
/// `malloc` won't allocate anything but also won't produce a SegFault
pub trait SliceCPtr {
    /// The Target for the trait.
    /// this trait can't be generic because it should only be implemented once per type
    /// (See [Associated Types][https://doc.rust-lang.org/rust-by-example/generics/assoc_items/types.html])
    type Target;
    /// This function is what will produce a valid C pointer to the target
    /// even if the target is 0 sized (and rust will produce a C *invalid* pointer for it )
    fn as_c_ptr(&self) -> *const Self::Target;
}

impl<T> SliceCPtr for [T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            EMPTY.as_ptr() as *const _
        } else {
            self.as_ptr()
        }
    }
}

impl SliceCPtr for str {
    type Target = u8;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            EMPTY.as_ptr() as *const _
        } else {
            self.as_ptr()
        }
    }
}
