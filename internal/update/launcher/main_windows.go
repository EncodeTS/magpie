// Command launcher is magpie.com, the console program magpie writes
// beside the Windows app (update.EnsureCompanion, #3737).
//
// The app is linked with -H windowsgui so that a double click opens no
// console window, and a shell doesn't wait for such a program: `magpie
// plugin login` in PowerShell or cmd gave the prompt back at once, printed
// after it, and the shell and magpie read the same keys. A shell looks for
// `magpie` by PATHEXT, which lists .COM before .EXE, so it runs this
// instead: a console program, which the shell waits for. It runs the app
// with this console's standard handles, waits for it and exits with its
// code. A command that opens the app's window (none, app, gui, tray,
// panel, a magpie:// link) is started and left to run, as it was.
//
// The app it runs is named in this file's last bytes (update.comText),
// so a download kept as magpie-windows-amd64.exe is run by its own name.
package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	self, err := os.Executable()
	if err != nil {
		fail(err)
	}
	target := filepath.Join(filepath.Dir(self), targetName(self))
	line := windows.UTF16PtrToString(windows.GetCommandLine())
	cmdline := `"` + target + `"`
	if rest := argsOf(line); rest != "" {
		cmdline += " " + rest
	}
	if opensWindow(os.Args[1:]) {
		// the app's window, which outlives the terminal: started on its
		// own, with no console, as a double click starts it
		var si windows.StartupInfo
		si.Cb = uint32(unsafe.Sizeof(si))
		var pi windows.ProcessInformation
		t, _ := windows.UTF16PtrFromString(target)
		c, _ := windows.UTF16PtrFromString(cmdline)
		if err := windows.CreateProcess(t, c, nil, nil, false, windows.DETACHED_PROCESS|windows.CREATE_NEW_PROCESS_GROUP, nil, nil, &si, &pi); err != nil {
			fail(err)
		}
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		return
	}
	// Ctrl+C reaches every program on this console, the app too, which
	// ends as it chooses; this one waits for it. A handler, not ignoring
	// the signal: that would be inherited, and the app would never see it.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	for i, f := range files {
		if f == nil { // started with no such stream: the app gets NUL
			if files[i], err = os.OpenFile(os.DevNull, os.O_RDWR, 0); err != nil {
				fail(err)
			}
		}
	}
	// update.ComEnv: the app keeps these handles and borrows this console
	p, err := os.StartProcess(target, nil, &os.ProcAttr{
		Files: files,
		Env:   append(os.Environ(), "MAGPIE_COM=1"),
		Sys:   &syscall.SysProcAttr{CmdLine: cmdline},
	})
	if err != nil {
		fail(err)
	}
	job := bindChildJob(p.Pid)
	st, err := p.Wait()
	if job != 0 {
		_ = windows.CloseHandle(job)
	}
	if err != nil {
		fail(err)
	}
	os.Exit(st.ExitCode())
}

// bindChildJob ties child pid to an anonymous Windows Job Object configured
// with KILL_ON_JOB_CLOSE so killing magpie.com also terminates the child
// magpie.exe instead of leaving an orphan serve process (#6806).
func bindChildJob(pid int) windows.Handle {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return 0
	}
	err = windows.AssignProcessToJobObject(job, proc)
	_ = windows.CloseHandle(proc)
	if err != nil {
		_ = windows.CloseHandle(job)
		return 0
	}
	return job
}

func fail(err error) {
	os.Stderr.WriteString("magpie: " + err.Error() + "\n")
	os.Exit(1)
}
