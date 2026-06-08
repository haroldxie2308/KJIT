use std::ffi::c_void;
use std::path::{Path, PathBuf};

use libloading::{Library, Symbol};

pub type NativeHandle = u32;

const INVALID_HANDLE: NativeHandle = 0;
const BORDER_CHARS: [u32; 11] = [
    '┌' as u32,
    '┐' as u32,
    '└' as u32,
    '┘' as u32,
    '─' as u32,
    '│' as u32,
    '┬' as u32,
    '┴' as u32,
    '├' as u32,
    '┤' as u32,
    '┼' as u32,
];

const BLACK: [u16; 4] = [0, 0, 0, 0xffff];
const WHITE: [u16; 4] = [0xffff, 0xffff, 0xffff, 0xffff];
const CYAN: [u16; 4] = [0, 0xffff, 0xffff, 0xffff];
const YELLOW: [u16; 4] = [0xffff, 0xffff, 0, 0xffff];

type FnCreateRenderer = unsafe extern "C" fn(u32, u32, u8, u8, *mut c_void) -> NativeHandle;
type FnDestroyRenderer = unsafe extern "C" fn(NativeHandle);
type FnSetupTerminal = unsafe extern "C" fn(NativeHandle, bool);
type FnRestoreTerminalModes = unsafe extern "C" fn(NativeHandle);
type FnResizeRenderer = unsafe extern "C" fn(NativeHandle, u32, u32);
type FnRender = unsafe extern "C" fn(NativeHandle, bool) -> u8;
type FnSetUseThread = unsafe extern "C" fn(NativeHandle, bool);
type FnSetClearOnShutdown = unsafe extern "C" fn(NativeHandle, bool);
type FnSetTerminalTitle = unsafe extern "C" fn(NativeHandle, *const u8, u32);
type FnEnableMouse = unsafe extern "C" fn(NativeHandle, bool);
type FnGetNextBuffer = unsafe extern "C" fn(NativeHandle) -> NativeHandle;
type FnBufferClear = unsafe extern "C" fn(NativeHandle, *const u16);
type FnBufferDrawText = unsafe extern "C" fn(
    NativeHandle,
    *const u8,
    u32,
    u32,
    u32,
    *const u16,
    *const u16,
    u32,
);
type FnBufferDrawBox = unsafe extern "C" fn(
    NativeHandle,
    i32,
    i32,
    u32,
    u32,
    *const u32,
    u32,
    *const u16,
    *const u16,
    *const u16,
    *const u8,
    u32,
    *const u8,
    u32,
);
type FnBufferFillRect = unsafe extern "C" fn(NativeHandle, u32, u32, u32, u32, *const u16);

#[derive(Debug)]
pub enum OpenTuiLoadError {
    MissingPath,
    Library(String),
    Symbol(String),
}

impl std::fmt::Display for OpenTuiLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPath => write!(
                f,
                "set KJIT_OPENTUI_LIB_PATH or KJIT_OPENTUI_ROOT to a libopentui.dylib path"
            ),
            Self::Library(message) => write!(f, "failed to load OpenTUI library: {message}"),
            Self::Symbol(message) => write!(f, "failed to bind OpenTUI symbol: {message}"),
        }
    }
}

impl std::error::Error for OpenTuiLoadError {}

pub struct OpenTuiBackend {
    _lib: Library,
    destroy_renderer: FnDestroyRenderer,
    setup_terminal: FnSetupTerminal,
    restore_terminal_modes: FnRestoreTerminalModes,
    resize_renderer: FnResizeRenderer,
    render: FnRender,
    set_use_thread: FnSetUseThread,
    set_clear_on_shutdown: FnSetClearOnShutdown,
    set_terminal_title: FnSetTerminalTitle,
    enable_mouse: FnEnableMouse,
    get_next_buffer: FnGetNextBuffer,
    buffer_clear: FnBufferClear,
    buffer_draw_text: FnBufferDrawText,
    buffer_draw_box: FnBufferDrawBox,
    buffer_fill_rect: FnBufferFillRect,
    renderer: NativeHandle,
}

impl OpenTuiBackend {
    pub fn load(width: u32, height: u32) -> Result<Self, OpenTuiLoadError> {
        let path = resolve_library_path()?;
        let lib = unsafe { Library::new(&path) }
            .map_err(|err| OpenTuiLoadError::Library(format!("{}: {}", path.display(), err)))?;

        macro_rules! load {
            ($name:literal, $ty:ty) => {{
                unsafe {
                    let symbol: Symbol<'_, $ty> = lib
                        .get(concat!($name, "\0").as_bytes())
                        .map_err(|err| OpenTuiLoadError::Symbol(format!("{}: {}", $name, err)))?;
                    *symbol
                }
            }};
        }

        let create_renderer = load!("createRenderer", FnCreateRenderer);
        let destroy_renderer = load!("destroyRenderer", FnDestroyRenderer);
        let setup_terminal = load!("setupTerminal", FnSetupTerminal);
        let restore_terminal_modes = load!("restoreTerminalModes", FnRestoreTerminalModes);
        let resize_renderer = load!("resizeRenderer", FnResizeRenderer);
        let render = load!("render", FnRender);
        let set_use_thread = load!("setUseThread", FnSetUseThread);
        let set_clear_on_shutdown = load!("setClearOnShutdown", FnSetClearOnShutdown);
        let set_terminal_title = load!("setTerminalTitle", FnSetTerminalTitle);
        let enable_mouse = load!("enableMouse", FnEnableMouse);
        let get_next_buffer = load!("getNextBuffer", FnGetNextBuffer);
        let buffer_clear = load!("bufferClear", FnBufferClear);
        let buffer_draw_text = load!("bufferDrawText", FnBufferDrawText);
        let buffer_draw_box = load!("bufferDrawBox", FnBufferDrawBox);
        let buffer_fill_rect = load!("bufferFillRect", FnBufferFillRect);

        let renderer = unsafe { create_renderer(width, height, 0, 1, std::ptr::null_mut()) };
        if renderer == INVALID_HANDLE {
            return Err(OpenTuiLoadError::Library(
                "createRenderer returned an invalid handle".to_string(),
            ));
        }

        let backend = Self {
            _lib: lib,
            destroy_renderer,
            setup_terminal,
            restore_terminal_modes,
            resize_renderer,
            render,
            set_use_thread,
            set_clear_on_shutdown,
            set_terminal_title,
            enable_mouse,
            get_next_buffer,
            buffer_clear,
            buffer_draw_text,
            buffer_draw_box,
            buffer_fill_rect,
            renderer,
        };
        unsafe {
            (backend.set_use_thread)(backend.renderer, false);
            (backend.set_clear_on_shutdown)(backend.renderer, true);
            (backend.enable_mouse)(backend.renderer, true);
        }
        Ok(backend)
    }

    pub fn setup_terminal(&self) {
        unsafe { (self.setup_terminal)(self.renderer, true) };
    }

    pub fn restore_terminal_modes(&self) {
        unsafe { (self.restore_terminal_modes)(self.renderer) };
    }

    pub fn resize(&self, width: u32, height: u32) {
        unsafe { (self.resize_renderer)(self.renderer, width, height) };
    }

    pub fn render(&self, force: bool) {
        unsafe {
            let _ = (self.render)(self.renderer, force);
        }
    }

    pub fn set_title(&self, title: &str) {
        unsafe {
            (self.set_terminal_title)(self.renderer, title.as_ptr(), title.len() as u32);
        }
    }

    pub fn next_buffer(&self) -> NativeHandle {
        unsafe { (self.get_next_buffer)(self.renderer) }
    }

    pub fn clear(&self, buffer: NativeHandle) {
        unsafe { (self.buffer_clear)(buffer, BLACK.as_ptr()) };
    }

    pub fn draw_text(
        &self,
        buffer: NativeHandle,
        text: &str,
        x: u32,
        y: u32,
        fg: &[u16; 4],
        bg: Option<&[u16; 4]>,
    ) {
        let bg_ptr = bg.map_or(std::ptr::null(), |value| value.as_ptr());
        unsafe {
            (self.buffer_draw_text)(
                buffer,
                text.as_ptr(),
                text.len() as u32,
                x,
                y,
                fg.as_ptr(),
                bg_ptr,
                0,
            );
        }
    }

    pub fn draw_box(
        &self,
        buffer: NativeHandle,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        title: &str,
        border: &str,
        fill: bool,
        border_fg: &[u16; 4],
        background: &[u16; 4],
        title_fg: &[u16; 4],
    ) {
        let packed = 0b1111 | if fill { 1 << 4 } else { 0 };
        unsafe {
            (self.buffer_draw_box)(
                buffer,
                x,
                y,
                width,
                height,
                BORDER_CHARS.as_ptr(),
                packed,
                border_fg.as_ptr(),
                background.as_ptr(),
                title_fg.as_ptr(),
                title.as_ptr(),
                title.len() as u32,
                border.as_ptr(),
                border.len() as u32,
            );
        }
    }

    pub fn fill_rect(&self, buffer: NativeHandle, x: u32, y: u32, width: u32, height: u32, bg: &[u16; 4]) {
        unsafe { (self.buffer_fill_rect)(buffer, x, y, width, height, bg.as_ptr()) };
    }

    pub fn palette(&self) -> Palette {
        Palette
    }
}

impl Drop for OpenTuiBackend {
    fn drop(&mut self) {
        unsafe {
            (self.restore_terminal_modes)(self.renderer);
            (self.destroy_renderer)(self.renderer);
        }
    }
}

fn resolve_library_path() -> Result<PathBuf, OpenTuiLoadError> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("KJIT_OPENTUI_LIB_PATH") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(root) = std::env::var_os("KJIT_OPENTUI_ROOT") {
        candidates.push(Path::new(&root).join("packages/core/node_modules/@opentui/core-darwin-arm64/libopentui.dylib"));
        candidates.push(Path::new(&root).join("node_modules/@opentui/core-darwin-arm64/libopentui.dylib"));
    }
    if let Some(root) = std::env::var_os("OPENTUI_ROOT") {
        candidates.push(Path::new(&root).join("packages/core/node_modules/@opentui/core-darwin-arm64/libopentui.dylib"));
        candidates.push(Path::new(&root).join("node_modules/@opentui/core-darwin-arm64/libopentui.dylib"));
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness crate has a parent repo directory");
    candidates.push(repo_root.join("../opentui/packages/core/node_modules/@opentui/core-darwin-arm64/libopentui.dylib"));
    candidates.push(repo_root.join("../opentui/node_modules/@opentui/core-darwin-arm64/libopentui.dylib"));

    candidates
        .into_iter()
        .find(|path| path.exists())
        .ok_or(OpenTuiLoadError::MissingPath)
}

fn _bg(color: [u16; 4]) -> [u16; 4] {
    color
}

#[allow(dead_code)]
pub(crate) fn palette() -> Palette {
    Palette
}

pub struct Palette;

impl Palette {
    pub fn black(&self) -> &'static [u16; 4] {
        &BLACK
    }
    pub fn white(&self) -> &'static [u16; 4] {
        &WHITE
    }
    pub fn cyan(&self) -> &'static [u16; 4] {
        &CYAN
    }
    pub fn yellow(&self) -> &'static [u16; 4] {
        &YELLOW
    }
}
