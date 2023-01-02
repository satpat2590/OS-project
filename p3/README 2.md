# Assignment #3: Adding Incremental Persistence

The purpose of this assignment is to gain experience with nuanced code for
persistence.

## Do This First

Immediately after pulling `p3` from Bitbucket, you should start a container,
navigate to the `p3` folder, and type `chmod +x solutions/*.exe`.  This command
only needs to be run once.  It will make sure that certain files from the
assignment have their executable bit set.

## Assignment Details

In the last assignment, we added a lot of new functionality to our server.
However, our persistence strategy was still somewhat unrealistic.  The way we
should think about persistence is "if persistence is important, then it needs to
be done well".

What does it mean to do persistence "well", though?  Certainly we don't want to
write the entire Storage object to disk every time it changes.  But how do we
know when a change is so important that it needs to be persisted *right away*? A
key property to think about here is *crash resilience*.  If the server crashes
and then restarts, then what can we guarantee to users?  It would be nice if we
could say "no matter what, if the server told you OK, your data won't get lost".

Our solution will be to transform our storage file: in addition to being able to
hold the entire state of the Storage object, it will now also be able to hold
"diffs".  A "diff" will be a small message, appended to the end of the file,
that describes how the Storage object has changed.

As an example, suppose that the directory had the key "k1" with the value "v1".
If a client performed an `upsert` to change the value to "v2", we would **not**
modify the representation of "v1" in the file.  Instead, we would add a message
of the form `"KVNEWVAL".sizeof("k1").sizeof("v2")."k1"."v2"`.  We could also
have messages to indicate that a key is deleted, or that a user's content
changed. For details about the new log messages, see `server/format.h`.

Making this work is challenging: we need to ensure that any update to the data
file is consistent with the state of the object in memory.  Put another way, the
update of a concurrent hash table needs to be *atomic with* an append to the
file.  Furthermore, each file update needs to be atomic.  So, for example, if
two server threads are simultaneously adding keys "k1" and "k2", then their
"KVNEWVAL" messages should not be interleaved.  In addition, if one thread
inserts "k1" and then another deletes "k1", the order of the add and delete
messages should be the same as the order in which threads performed their
operations.

If we want to be efficient, then it is not wise to have threads constantly open
and close the file... we will need to keep it open, perform appends to it, and
use `fflush()` and `fsync()` to ensure that data reaches the disk.  Note: in
real servers, read-only operations far exceed all other operations, so we
shouldn't worry that disk writes will be too frequent.

Our server will still support the `SAV` command, which will produce an optimal
representation of the Storage object (that is, `persist()` doesn't change!). But
now `load()` will need to be able to handle the case where there are diff
records at the end of the file, and any operation that modifies the Storage
object will need to append to the file.

Based on this description, you're probably thinking that most of your work will
be in `server/my_storage.cc`.  That's correct.  The only exception is if you
want to write some helper functions, in which case you can put them in
`server/persist.cc`.

Note that in this assignment, we are providing a complete concurrent hash map.
You may assume that any lambda that is passed to the map will run *atomically
with* the rest of a successful map operation.

## Getting Started

Your git repository has a new folder, `p3`, which contains a significant portion
of the code for the final solution to this assignment.  It also includes binary
files that represent much of the solution to assignment 2.  The `Makefile` has
been updated so that you do not need to have completed the first or second
assignment in order to get full credit for this assignment.

There is a test script called `scripts/p3.py`, which you can use to test your
code.  Note that these tests are not sufficient to show that your code is
persisting in a correct, thread-safe, consistent manner.  We will inspect your
code to evaluate its correctness in the face of concurrency.

## Tips and Reminders

You should probably start by tackling an individual diff message, and getting it
to work in `load()`.  Once you have figured out one, the others should not be
too hard.  But the synchronization and atomicity will be tricky.  Do not
underestimate the time it will take to produce a correct solution.

As in the last assignment, you should keep in mind that subsequent assignments
will build upon this... so as you craft a solution, be sure to think about how
to make it maintainable.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

As always, please be careful about not committing unnecessary files into your
repository.

Your server should **not** store plain-text passwords in the file.

In this assignment, you will need to make use of the lambda arguments to the
methods of the concurrent hash table.  This is very powerful: by allowing a
lambda to run while locks are held, it is easier to ensure two-phase locking
(2pl).  Remember: you should make sure that your code obeys 2pl so that it is
easy to argue its correctness.

## Grading

The `scripts` folder has a script that exercises the main portions of the
assignment: diff-based persistence, atomic log messages, flushing, and correct
use of files.  The script uses a specialized `Makefile` that integrates some of
the solution code with some of your code, so that you can get partial credit
when certain portions of your code work.  Note that this `Makefile` is very
strict: it will crash on any compiler warning.  You should *not* turn off the
warnings; they are there to help you.  If your code does not compile with this
script, you will not receive any credit.  If you have partial solutions and you
do not know how to coerce the code into being warning-free, you should ask the
professors or TAs.

If the script passes when using your client with our server, and when using our
client with your server, then you will receive full "functionality" points.  We
will manually inspect your code to determine if it is correct with regard to
other properties.  As before, we reserve the right to deduct "style" points if
your code is especially convoluted.  Please be sure to use your tools well.  For
example, Visual Studio Code (and emacs, and vim) have features that auto-format
your code.  You should use these features.

While it is our intention to give partial credit, *no credit will be given for
code that does not compile without warnings.*  If you decide to move functions
between files, or add files, or do other things that break the scripts in the
grading folder, then you will lose at least 10%. If you think some change is
absolutely necessary, speak with the professor first.

There are four main graded portions of the assignment:

* Does the server write incrementally to the file?
* Does the server load diffs correctly, and persist correctly?
* Are the diffs atomic?
* Are the diffs produced in a consistent manner?

## Notes About the Reference Solution

Let's use `insert` as an example to illustrate some important issues about the
interaction between persistence and concurrency.  Suppose that two threads are
inserting two different k/v pairs at the same time... does it matter which order
they appear in the log?  Probably not.  But suppose that two threads are
`upserting` two different values for the same key at the same time... now it does
matter which order they appear in the log.

From the above, you should recognize that we are going to have to do some amount
of writing to a file *while holding a lock*.  That is, this isn't going to be
like the implementation of `persist()`, where we needed to use 2pl on the entire
table, but it's also not like the first assignment where we didn't care much
about atomicity.

One thing that works to our advantage is that a single `write()` system call
*will be atomic*.  But how do we get our writes to happen while holding locks?
The answer, as you have probably guessed, is lambdas.  Most of the functions in
`concurrenthashmap.h` take an extra lambda (or two!).

The `my_storage.cc` implementation is where all of the work will be.  The
reference solution grew by about 175 lines, relative to assignment 2.  In
particular, `load()` grew to about 120 lines of code, in order to handle all of
the new entry types that are possible in the file.

You may be starting to feel like `my_storage.cc` is getting too big.  We have
added two new files, `persist.h` and `persist.cc`, which are currently empty.
If you find that it is useful to put some code into these files, you may.
However, you must ensure that `persist.h` is *only* included by `my_storage.cc`.
In the reference solution, we created three functions, for a total of 66 lines
of code in `persist.cc`.

## Collaboration and Getting Help

You may work in teams of 2 for this assignment.  If you plan to work in a team,
you must notify the instructor by October 15th, so that we can set up your
repository access.  If you notify us after that date, we will deduct 10 points.
If you wish to have a different team than in the last assignment, or to disband
your team and work alone, please contact the professors by October 15th. If you
are working in a team, you should **pair program** for the entire assignment.
After all, your goal is to learn together, not to each learn half the material.

If you require help, you may seek it from any of the following sources:

* The professor and TAs, via office hours or Piazza
* The Internet, as long as you use the Internet as a read-only resource and do
  not post requests for help to online sites.

It is not appropriate to share code with past or current CSE 303 / CSE 403
students, unless you are sharing code with your teammate.

If you are familiar with `man` pages, please note that the easiest way to find a
man page is via Google.  For example, typing `man printf` will probably return
`https://linux.die.net/man/3/printf` as one of the first links.  It is fine to
use Google to find man pages.

StackOverflow is a wonderful tool for professional software engineers.  It is a
horrible place to ask for help as a student.  You should feel free to use
StackOverflow, but only as a *read only* resource.  In this class, you should
**never** need to ask a question on StackOverflow.

## Deadline

You should be done with this assignment before 11:59 PM on November 4th, 2022.
Please be sure to `git commit` and `git push` before that time, so that we can
promptly collect and grade your work.
