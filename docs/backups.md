# <img src="img/ring-5.svg" width="33" alt=""> Backups

What the coordinator backs up every night, how to copy the backups home, and why a hacked coordinator cannot use them against you.

Part of the [dryserver README](../README.md).

The coordinator backs itself up every night, around 02:30: the cluster's
datastore and token, the list of machines, its WireGuard and SSH keys and
dryserver's settings. Each backup is encrypted to
`secrets/backup_ed25519.pub`, a key the first USB build makes on your
computer. The coordinator has only that public half: it can make backups
but cannot read one. For the copy of the cluster's datastore k3s pauses
for a moment; the apps keep running.

```sh
./dryserver backup-pull    # copy the newest backups into secrets/backups/
```

It copies them over your own SSH login, checks each one's size and the
coordinator's signature, and never replaces a file you already have. Both
sides keep the newest backup of each of the last 7 days and of each of the
last 4 weeks that have one. Your copies are thinned only by backups that
are on your computer or checked out in this pull, never by names the
coordinator lists: a hacked coordinator listing backups it cannot deliver
removes nothing. Names dated more than a day after your computer's clock,
and files listed above 4 GiB, are not copied. Pull now and then: if the
coordinator's disk dies, the backups on it die with it.

A coordinator hacked as root can sign anything with its host key and make
backups that open (it has the public key they are encrypted to), so a
backup that checks out is no proof that it is a good one. What it cannot
change is your computer's clock. So a pull takes only backups dated after
the newest copy you have, oldest first, and says which older ones it did
not copy: your copies are pushed out only by newer days and weeks, as time
would push them out anyway, never by backups dated back into their days.
And the weekly copies you had before a pull stay through that pull
(they go at the next one when newer weeks took their place): one pull
never removes every copy you have. The copies from before a break-in are
the ones you need, so pull often and look at what each pull says.

On the coordinator, the backups are in `/var/lib/dryserver-backup` (root's,
readable by your login; not inside `/var/lib/dryserver`, which belongs to
the account every server reaches), `sudo dryserver backup` makes one now,
`/var/lib/dryserver-backup/last.json` says how the last one went, and
`journalctl -u dryserver-backup` has the details. On a coordinator
installed when backups were kept in `/var/lib/dryserver/backups`, the next
backup moves them over, removes that directory and the ACL entry it had for
your login, and touches nothing there it did not make. Restoring is not built
yet; to look inside one:
`age -d -i secrets/backup_ed25519 FILE | tar -tv`.

**Back up `secrets/backup_ed25519`** with your other secrets: without it no
backup can be opened.
