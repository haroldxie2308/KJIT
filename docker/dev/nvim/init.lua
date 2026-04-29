vim.g.mapleader = " "

vim.opt.number = true
vim.opt.relativenumber = true
vim.opt.signcolumn = "yes"
vim.opt.termguicolors = true
vim.opt.mouse = "a"
vim.opt.expandtab = true
vim.opt.shiftwidth = 4
vim.opt.tabstop = 4
vim.opt.smartindent = true
vim.opt.hlsearch = true
vim.opt.ignorecase = true
vim.opt.smartcase = true
vim.opt.incsearch = true
vim.opt.swapfile = false

vim.g.NERDTreeMouseMode = 2
vim.opt.packpath:append("/opt/kjit/nvim/site")
pcall(vim.cmd, "packadd tokyonight.nvim")
pcall(vim.cmd, "packadd nerdtree")

local ok_tokyonight, tokyonight = pcall(require, "tokyonight")
if ok_tokyonight then
    tokyonight.setup({
        style = "night",
        terminal_colors = true,
        styles = {
            comments = { italic = false },
            keywords = { italic = false },
        },
    })
    vim.cmd.colorscheme("tokyonight-night")
end

local function map(mode, lhs, rhs, desc)
    vim.keymap.set(mode, lhs, rhs, { silent = true, desc = desc })
end

map("n", "gd", vim.lsp.buf.definition, "Go to definition")
map("n", "gr", vim.lsp.buf.references, "Find references")
map("n", "K", vim.lsp.buf.hover, "Hover")
map("n", "<leader>rn", vim.lsp.buf.rename, "Rename")
map("n", "<leader>ca", vim.lsp.buf.code_action, "Code action")
map("n", "[d", vim.diagnostic.goto_prev, "Previous diagnostic")
map("n", "]d", vim.diagnostic.goto_next, "Next diagnostic")
map("n", "<leader>e", vim.diagnostic.open_float, "Line diagnostics")
map("n", "<leader>q", vim.diagnostic.setloclist, "Diagnostics list")
map("n", "<leader>f", function()
    vim.lsp.buf.format({ async = true })
end, "Format")
map("n", "<C-n>", "<cmd>NERDTreeToggle<CR>", "Toggle NERDTree")
map("n", "<leader>nt", "<cmd>NERDTreeToggle<CR>", "Toggle NERDTree")
map("n", "<leader>nf", "<cmd>NERDTreeFind<CR>", "Reveal file in NERDTree")

vim.api.nvim_create_autocmd("BufEnter", {
    callback = function()
        if vim.fn.winnr("$") == 1 and vim.bo.filetype == "nerdtree" then
            vim.cmd("quit")
        end
    end,
})

local function find_root(start)
    local markers = { "rust-project.json", "Cargo.toml", ".git" }
    local found = vim.fs.find(markers, { upward = true, path = start })[1]
    if found then
        return vim.fs.dirname(found)
    end
    return vim.loop.cwd()
end

local function rust_analyzer_cmd()
    local cmd = { "/workspace/.kjit/bin/rust-analyzer" }
    if vim.fn.executable(cmd[1]) ~= 1 then
        cmd = { "rust-analyzer" }
    end
    return cmd
end

local function start_rust_analyzer(bufnr)
    bufnr = bufnr or vim.api.nvim_get_current_buf()
    if vim.bo[bufnr].filetype ~= "rust" then
        return
    end

    local root = find_root(vim.api.nvim_buf_get_name(bufnr))
    local rust_project = root .. "/rust-project.json"

    vim.lsp.start({
        name = "rust-analyzer",
        cmd = rust_analyzer_cmd(),
        root_dir = root,
        settings = {
            ["rust-analyzer"] = {
                linkedProjects = vim.fn.filereadable(rust_project) == 1 and { rust_project } or nil,
                procMacro = {
                    enable = true,
                },
                check = {
                    command = "clippy",
                },
            },
        },
    }, { bufnr = bufnr })
end

vim.api.nvim_create_autocmd({ "FileType", "BufEnter" }, {
    pattern = "rust",
    callback = function(args)
        start_rust_analyzer(args.buf)
    end,
})

vim.api.nvim_create_user_command("KjitRustAnalyzerStart", function()
    start_rust_analyzer(0)
end, {})

vim.api.nvim_create_user_command("KjitLspInfo", function()
    local bufnr = vim.api.nvim_get_current_buf()
    local name = vim.api.nvim_buf_get_name(bufnr)
    local root = find_root(name)
    local rust_project = root .. "/rust-project.json"
    local lines = {
        "buffer: " .. (name ~= "" and name or "[No Name]"),
        "filetype: " .. vim.bo[bufnr].filetype,
        "root: " .. root,
        "rust-project.json: " .. (vim.fn.filereadable(rust_project) == 1 and rust_project or "missing"),
        "rust-analyzer executable: " .. tostring(vim.fn.executable(rust_analyzer_cmd()[1])),
        "active clients: " .. vim.inspect(vim.lsp.get_active_clients({ bufnr = bufnr })),
    }
    print(table.concat(lines, "\n"))
end, {})
