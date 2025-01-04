# Project 1: Defend the Flag

## 1 | General Information
- This is the second of two graded course projects. This project will determine
  **8.33% of your final grade**. Not handing in this project will result in a 1
  for this project, but passing the course is still possible.
- This project must be completed **individually**. Discussions about the
  implementation and sharing of code is not permitted.
- **Plagiarism checks** will be performed. In addition to manual checks we use
  an online plagiarism checker hosted by a foreign research institute.
  Therefore, please ensure there is no sensitive personal information in your
  code.
- The due date of this project is **2024-12-13 23:59**. This is a hard deadline
  that will be automatically enforced.
- The instructions in this document are very limited---this is on purpose. Most
  information needed for this project is very well documented in man pages.
  Familiarizing yourself with these is one of the goals of this project.

## 2 | Your Task
In this project, you are given a virtual machine and are supposed to analyze and
implement common security measures you have seen in this course. Your task is to
create a program which fixes all of these issues automatically. We assume some
enough familiarity with Linux systems[^1] to navigate the shell and execute
basic commands.

Below you are given a list of tasks, either consisting of problems or issues
with the current setup. Some of these might not be resolvable before you solved
related problems, it is up to you to figure out these depedencies yourself.

You are permitted (and even encouraged) to install new packages on the machine,
inspect and change configuration files, and so on. See the "Tips" section for
some helpful hints.

Your solution repository is automatically cloned into your student's home
directory for your convenience.

### 2.1 | Internet connectivity

The VM has issues reaching the internet. Find out why this is the case and
resolve the issue.

> Tip: Try pinging the VM from your end. What do you see? Why might that happen?

### 2.2 | Secure the database server
Your VM is running a "database server" which is listening for TCP connections on
port 5432. Ensure that only the grading server running at
`grader.dtf.netsec.inf.ethz.ch` is able to access the database server from the
internet.

### 2.3 | You have been pwned!
There have been reports that malicious actors exfiltrated secure passwords from
your VM via HTTP. Find out how this happened and fix it.

> Your VM is running the well known and widely deployed
> [nginx](https://nginx.org) webserver, you can use `systemctl status nginx` to
> view its status.

### 2.4 | TLS certificate via ACME
Currently the VM serves HTTPS traffic using a self-signed certificate. From the
course you recall that while the data exchanged is still encrypted, a proper
chain of trust would be preferable. The first project dealt with you
implementing a client for the ACME protocol, while this one requires you to use
an ACME client to acquire a TLS certificate.

The ACME directory from which you should order the certificate is located at
`acme.dtf.netsec.inf.ethz.ch`. The ACME server directory is at
`/acme/default/directory`. Your task is to request a certificates for the domain name
`nethz.student.dtf.netsec.inf.ethz.ch` where `nethz` is your ETH username and
configure TLS traffic in the nginx web server.

> This domain only resolves internally, do not worry if you can't see the DNS
> records from your client machine.

### 2.5 | TLS configuration
Inspect the webserver's TLS configuration. Is it secure? If not fix the
identified issues and make it secure.

## 3 | Tips

Below you can find a list of tips and tricks related to debugging your Linux
system.

* Program configuration is usually found under `/etc/<program_name>`.
* To locate a file by name, use the `find` command. To find files with content
  you can use `grep -r`. The `man` page of both commands explains how to use
  these.
* You can find logs either using `journalctl` or as files located in `/var/log`.
  Note that you might need to use `sudo` in order to access these!
    * To follow logs live, you can use either `journalctl -f` or `tail -f
      /path/to/file`.
    * `journalctl -u unit` only displays logs for `unit`
* `systemctl` is a very useful command
    * `systemctl status` lists information about the current running services on the system
    * `systemctl status service` lists information about that service
    * `systemctl restart service` restarts a service
* `man` pages are very helpful in finding information about various services,
  and often also link to external documentation. You can open a commands `man`
  page by typing `man command`. For listing manpages you can use `whatis`
  instead.

## 4 | Testing

You can test your project using the grading system, which runs at
[`grader.dtf.netsec.inf.ethz.ch`](https://grader.dtf.netsec.inf.ethz.ch) using
the "Check VM" button. Testing is done directly against your VM, and any test
scores are _not_ graded.

## 5 | Grading

You should submit your code by pushing it to a personal repository we have set up for you at
 ```
 https://gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-dtf/netsec-2024-student-dtf/<nethz_id>-dtf-project
 ```
 
There is no continuous integration set up for your repository, instead you have
to manually start the grading process by clicking the "Grade Solution" button. The
grading process will run in the background and take a while to complete, you can
continue to work on your VM in the meantime.

Your score for the project will be calculated as follows:
```
final_score = 1 + nr of completed tasks
```
You can see the number of completed tasks in the web interface of the grader.
**We will not make adjustments to this score.** The only exception to this is
when we notice that you did not follow the project rules or when we detect
plagiarism. If you experience problems with the grader, you must address these
**before** the deadline.

Note also that the grading server does not have unlimited resources. It is
likely that testing times will increase when many students start submitting
solutions at the same time. We will not accept this as an excuse for failed
tests and we will not extend the deadline because of this: there is plenty of
time to submit.

[^1]: A cheat sheet is available [here](https://www.guru99.com/linux-commands-cheat-sheet.html).
