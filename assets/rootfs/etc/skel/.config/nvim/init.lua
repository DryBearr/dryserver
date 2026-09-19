-- dryserver default Neovim config. Replace it with your own any time.

vim.opt.number = true
vim.opt.relativenumber = true
vim.opt.mouse = "a"
vim.opt.expandtab = true
vim.opt.shiftwidth = 4
vim.opt.tabstop = 4
vim.opt.ignorecase = true
vim.opt.smartcase = true
vim.opt.undofile = true
vim.opt.termguicolors = true

-- Yank and paste use the system clipboard ("+" register).
vim.opt.clipboard = "unnamedplus"

-- Over SSH the server has no clipboard of its own, so yanks are sent to
-- your desktop clipboard through the terminal (OSC 52). Most terminals
-- refuse to let a program read the desktop clipboard, so to paste from the
-- desktop use your terminal's paste key (Ctrl+Shift+V); "p" pastes the
-- last yank from this Neovim.
if os.getenv("SSH_TTY") or os.getenv("SSH_CONNECTION") then
  local osc52 = require("vim.ui.clipboard.osc52")
  local function paste()
    return { vim.fn.split(vim.fn.getreg(""), "\n"), vim.fn.getregtype("") }
  end
  vim.g.clipboard = {
    name = "OSC 52",
    copy = { ["+"] = osc52.copy("+"), ["*"] = osc52.copy("*") },
    paste = { ["+"] = paste, ["*"] = paste },
  }
end
