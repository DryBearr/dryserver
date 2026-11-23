# The dryserver screens

How every screen looks and behaves. The rule for any new screen: it is
built from the parts below, uses the keys below for the same things, and
says what to do next in plain words.

## Direction

Simple pixel art, polished, dark. The terminal's cells are the pixels: a
half block (`▀`) with one colour above and another below draws two square
pixels per cell, which is how the snake is drawn. Everything else is flat:
coal surfaces, a slightly raised surface for bars and panels, no line
borders around content, no decoration that carries no meaning. The one
emblem is the ouroboros, and it means something wherever it shows: the
snake grows around the ring as work is done and bites its tail when it is
finished.

## Colour

Each colour has one job. The same job always gets the same colour.

| Token | True colour | 256 colours | 16 colours (console) | Job |
|---|---|---|---|---|
| coal | `#140C0A` | 233 | terminal's own | the screen |
| raised | `#1E1513` | 234 | terminal's own | header and footer bars, panels, key caps |
| shade | `#3A1A12` | 52 | none (reverse not used) | the selected row's background |
| bone | `#E6DCCF` | 253 | terminal's own | body text |
| ember | `#F25C38` | 203 | light red | what you act on: the selected row's mark, the next step, the primary key |
| flame | `#EE8434` | 208 | yellow | titles and headings |
| gold | `#D2A23A` | 178 | light yellow | done, signed, healthy; the keys you can press |
| violet | `#9A85D0` | 140 | magenta | hints, secondary text, waiting |
| ash | `#5E534F` | 240 | dark grey | structure: rules, empty progress, disabled |
| alarm | `#FF5E4D` bold | 203 bold | white on red, bold | something is wrong |

The snake's body runs through the eight colours of `theme::TRUE_BODY`,
head to tail. With `NO_COLOR` set, nothing is coloured and nothing is
painted: marks and words carry the meaning on their own.

Which tier a terminal gets: true colour when `COLORTERM` is `truecolor` or
`24bit` and `TERM` is not `linux`; 256 colours when `TERM` contains
`256color`; else 16 colours. Only the console tier draws with code page
437 glyphs (the installer runs there).

## Glyphs

| Meaning | Glyph | Console | Colour |
|---|---|---|---|
| done, signed, healthy | `✓` | `√` | gold |
| needs you, the next step | `●` | `•` | ember |
| waiting, in progress | `○` | `o` | violet |
| wrong | `!` | `!` | alarm |
| not yet, not available | `·` | `·` | ash |
| the selected row | `▌` at the left edge | `▌` | ember, on shade |
| busy | the spinner in `mod.rs` | same | ember |

A mark and its words always say the same thing: a mark never stands
alone without text.

## The frame

Every desktop screen is one frame, the full terminal:

```
 dryserver  Machines                              coordinator 10.1.0.60  ✓ answers
 Machines   Updates   Network
                                                                       
   Waiting to join  1                                                   
 ▌ ● node-3a2f      10.1.0.71      code 482 913   2m ago               ▐
                                                                       ▐
   Members  3                                                           
   ✓ coord          10.66.0.1      signed         seen 4s ago          
   ✓ node-a         10.66.0.2      signed         seen 9s ago          
   ! node-b         10.66.0.3      disk 93% full  seen 6s ago          
                                                                       
 ✓ Approved node-a. It joins within a minute.                          
  a  approve   x  reject   enter  more   ?  help   esc  back            
```

- **Header** (raised bar, one line): `dryserver` in flame, the place in
  bone, and on the right what the place depends on (the coordinator and
  whether it answers). Below it, the tabs when the place has more than
  one: the open tab in bone bold on shade, the others in violet. `tab`
  and `shift+tab` (or `←` `→`) switch.
- **Body**: everything else, three columns in from the left (the
  selection's `▌` sits in the second), at most 100 columns wide, under a
  blank line when the window has more than 24 rows. It scrolls when it does not fit, and the selected row
  always stays in view; a thin thumb on the right edge shows where you
  are. Long lines wrap at word boundaries and keep their indent; table
  cells are cut with `…` and shown whole in the details.
- **Notice** (one line above the footer): the answer to what you just
  did. Gold `✓` for done, alarm `!` for failed, violet for anything
  else. It stays until the next key.
- **Footer** (raised bar, one line): the keys that work right now, each
  key as a cap (gold on raised, `[a]` on the console) and what it does in
  violet. The most used first; `?` help and `esc` back always last. When
  they do not fit, the footer keeps the first ones and `?` shows all.
- **Too small**: under 80 × 24 the frame shows only "Make this window at
  least 80 × 24 (it is W × H)" and `q` quits.

## Parts

- **Section**: a heading in flame, sentence case, with a count in violet
  when it lists things (`Members  3`). One blank line before it.
- **Row**: a mark, then columns. The selected row has the `▌` bar and the
  shade background across the body's width.
- **Empty state**: what is missing, why, and the key that fixes it, never
  a bare "none". "No machine waits to join. Boot the USB stick on another
  laptop and choose server."
- **Problem card**: a raised panel with an alarm line (what happened: its
  first sentence in alarm bold, the rest in bone), then what to do, then
  the key that does it. Used for an unreachable
  coordinator, a changed host key, a missing key file, a stopped rollout.
- **Actions sheet**: `enter` on a row opens a raised panel listing what can
  be done to it, each with its key. Something that cannot be done now is
  listed in ash with the reason.
- **Panels** (confirm, help, actions sheet) go over the body, with a cell
  of plain screen round them; what is under them recedes toward the coal,
  so only the panel reads.
- **Confirm**: a raised panel over the body: the question, then one line
  per consequence, then `y` for yes and any other key for no. Signing,
  removing, closing a way in, publishing and flashing always confirm;
  reading never does.
- **Help** (`?`): a raised panel with every key of the place and one
  paragraph on what the place is for. Any key closes it.
- **Progress**: the ring grows as work is done (the snake, drawn in
  pixels with true colour, in blocks on the console), with the step, the
  elapsed time and a bar of half blocks in the snake's colours.
- **Form**: one step at a time with "Step 2 of 6" and the step's title,
  the fields of that step, and a review of every answer before saving.
  `enter` next, `shift+tab` previous, `esc` goes back one step (on the
  first step it leaves, asking first when something changed).

## Keys

The same key does the same thing on every screen. Letters are lowercase
only, so no two actions differ by shift.

| Key | Does |
|---|---|
| `↑` `↓` (`k` `j`) | move |
| `enter` | open, choose, or the actions of the selected row |
| `esc` | back one level; on Home, nothing |
| `q` | on Home: quit. Elsewhere: back, like `esc` |
| `ctrl+c` | quit from anywhere (asks first while a change runs) |
| `tab` `shift+tab`, `←` `→` | next and previous tab |
| `?` | help |
| `r` | look again now (live screens) |
| `pgup` `pgdn`, `home` `end` | scroll |
| `1`-`9` | on Home, open that place |

Actions, where they exist: `a` approve, `x` reject, `d` remove, `n` new,
`p` publish, `y` yes in a confirm. Anything else is in the actions sheet.

## Words

Sentence case. Plain verbs. A screen never tells you to type a command
when it can do the thing itself; when only the terminal can (sudo asks for
a password on each server), the screen leaves the terminal to it and comes
back. Errors say what happened, then what to do, then which key does it.
No capitals for emphasis: the colour and the mark carry it.

## Home

```
   [snake, 20 × 10 cells]   dryserver
                            your own server swarm

   Set up
 ▌ ✓  1  Config        coordinator 10.1.0.60, WiFi SNET2
   !  2  Installer     made by an older dryserver: build it again
   ·  3  USB stick     write the installer to a stick (needs sudo)

   Run
   ✓  4  Machines      coordinator and 2 servers, 1 waits to join
   ·  5  Apps
   ·  6  Outside
   ✓  7  Updates       release 1795400000
   !  8  Backups       newest copy is 9 days old: pull them

   When something is wrong
      9  Kill switch   cut the coordinator off from every server

   Next  Build the installer again (2): the stick has an older dryserver.
```

A window too short for the 20-column snake gets the same snake at 12
pixels (12 × 6 cells), with the Next line beside it, so all nine places
show at 80 × 24. Everything on Home comes from files on this computer, so it shows at
once and never waits for the network. The next step is the first of:
no config, a config with errors, no installer or one older than the
config or than this dryserver, no keys, no signed coordinator, no server,
backups older than 7 days. Under sudo only Installer and USB stick work;
the others are shown in ash with "open dryserver without sudo".

## Places

- **Config**: the form, by steps, with a review at the end.
- **Installer**: what will be built (config, tools, k3s), then progress
  with the ring and the last lines of the log; on failure the error card
  with the log's path and `r` to try again.
- **USB stick**: removable disks only, each with its size, model and what
  is on it; choosing one asks you to type its name; progress, then the
  read-back check.
- **Machines** (tabs Machines, Updates, Network):
  - Machines: waiting requests (code, address, age; a request without
    the stick's proof is marked and can only be rejected), then members
    with one health line each; `enter` opens the details and the actions.
    First run: a card "Sign your coordinator: its screen shows the code
    123 456" with `s`. A changed host key: a card with `n` to look at
    the new coordinator.
  - Updates: the release on every machine with the rollout's progress;
    `p` publish (the form, then the summary, then confirm); a stopped
    rollout is a card with "try again" and "skip this machine".
  - Network: unknown devices, cut-offs, warnings.
- **Apps**: apps with their state and server; `n` new, `d` remove,
  `enter` details; the way in from outside per app.
- **Outside**: each way in with its state and its host names; `enter`
  for its actions (open, sync, take a name over, close); a plan always
  shows every change before `y`.
- **Updates**: opens Machines on its Updates tab.
- **Backups**: the copies on this computer (newest first, age, size);
  `p` pulls newer ones from the coordinator with progress.
- **Kill switch**: what it does, the servers it reaches, then it leaves
  the terminal to `quarantine-all` (sudo asks on each server) and comes
  back with the result. Lift and status from the same place.

## Installer (on the machine)

The same frame and words on the 16-colour console, without the raised
bars: the header and footer are plain lines. Its steps are a sequence,
shown as "Step 2 of 5" with the ring: welcome (the machine, its disks,
its network, the role it will get), WiFi when needed, the form, the
checks, confirm with `YES`, the install with progress, then the pairing
code in large digits until the desktop approves it.

## Edge cases every screen handles

- A terminal under 80 × 24, and a resize at any moment.
- True colour, 256 colours, the 16-colour console, and `NO_COLOR`.
- Run with sudo: only the stick can be written; everything else explains.
- A missing config, installer, key, or signed list: an empty state that
  names the place that fixes it.
- The coordinator not answering, answering slowly, or answering with
  another host key; the screen never freezes and says how long it waits.
- Background work that fails or stops: a card, and the screen still works.
- Quitting while a change runs: asks once, and says what stops.
- Long names and many rows: cut in tables, whole in details, scrolling
  that keeps the selection in view.
- A paste where a key is expected does nothing.
