use core::cell::UnsafeCell;

#[cfg(feature = "huge-arena")]
const ARENA_SIZE: usize = 16 * 1024 * 1024;

#[cfg(all(feature = "large-arena", not(feature = "huge-arena")))]
const ARENA_SIZE: usize = 4 * 1024 * 1024;

#[cfg(not(any(feature = "large-arena", feature = "huge-arena")))]
const ARENA_SIZE: usize = 1024 * 1024;

struct BumpAllocator {
    arena: UnsafeCell<[u8; ARENA_SIZE]>,
    offset: UnsafeCell<usize>,
}

unsafe impl Sync for BumpAllocator {}

impl BumpAllocator {
    const fn new() -> Self {
        Self {
            arena: UnsafeCell::new([0u8; ARENA_SIZE]),
            offset: UnsafeCell::new(0),
        }
    }

    fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        unsafe {
            let offset = &mut *self.offset.get();
            let aligned = (*offset + align - 1) & !(align - 1);
            let new_offset = aligned + size;
            if new_offset > ARENA_SIZE {
                return core::ptr::null_mut();
            }
            *offset = new_offset;
            let arena = &mut *self.arena.get();
            arena.as_mut_ptr().add(aligned)
        }
    }

    fn reset(&self) {
        unsafe {
            *self.offset.get() = 0;
        }
    }
}

static ALLOCATOR: BumpAllocator = BumpAllocator::new();

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let ptr = ALLOCATOR.alloc(size as usize, 8);
    if ptr.is_null() {
        0
    } else {
        ptr as i32
    }
}

#[no_mangle]
pub extern "C" fn allocate(size: i32, _align: i32) -> i32 {
    alloc(size)
}

pub fn sdk_alloc(size: usize) -> *mut u8 {
    ALLOCATOR.alloc(size, 8)
}

pub fn sdk_reset() {
    ALLOCATOR.reset();
}
