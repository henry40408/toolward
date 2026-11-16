package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/henry40408/toolward/internal/config"
)

const about = "MCP proxy that keeps credentials out of agent-readable config files"

const configUsage = "Config file [default: ~/.config/toolward/config.json]"

// usageError is a mistake in the command line. It exits with code 2.
type usageError string

func (e usageError) Error() string { return string(e) }

// command is one subcommand. A group command has two words ("secret set").
type command struct {
	name        string
	summary     string
	positionals []string
	defineFlags func(flags *flag.FlagSet, inv *invocation)
	run         func(p process, inv *invocation) error
}

// invocation is what the command line asked for.
type invocation struct {
	command     *command
	showVersion bool
	helpText    string
	// configPath is empty when the user gave none: the default applies.
	configPath string
	arguments  []string
	tools      bool
	apply      bool
	format     string
}

var commands = []*command{
	{name: "secret set", summary: "Store a secret, read from a hidden prompt or from stdin", positionals: []string{"account"}, run: runSecretSet},
	{name: "secret delete", summary: "Remove a secret", positionals: []string{"account"}, run: runSecretDelete},
	{name: "auth login", summary: "Authorize in the browser and store the tokens in the credential store", positionals: []string{"server"}, run: runAuthLogin},
	{name: "auth logout", summary: "Remove the stored tokens", positionals: []string{"server"}, run: runAuthLogout},
	{name: "import", summary: "Move plaintext secrets of an existing mcp.json into the credential store", positionals: []string{"file"}, defineFlags: defineImportFlags, run: runImport},
	{name: "check", summary: "Validate the config and report which referenced secrets are missing", defineFlags: defineCheckFlags, run: runCheck},
	{name: "serve", summary: "Run the MCP proxy on stdio (this is what an agent's mcp.json should launch)", run: runServe},
}

func defineImportFlags(flags *flag.FlagSet, inv *invocation) {
	flags.BoolVar(&inv.apply, "apply", false, "Store the secrets and write the config; without it, only show the plan")
}

func defineCheckFlags(flags *flag.FlagSet, inv *invocation) {
	flags.BoolVar(&inv.tools, "tools", false, "Also connect to every server and list the tool names the agent will see")
	inv.format = "text"
	flags.Func("format", "`json` prints one JSON object for programs, never colored (text or json, default text)", func(value string) error {
		if value != "text" && value != "json" {
			return fmt.Errorf("invalid value %q for --format (possible values: text, json)", value)
		}
		inv.format = value
		return nil
	})
}

// parseInvocation reads the command line. flag.ErrHelp comes back with the
// help text in the invocation.
func parseInvocation(args []string) (*invocation, error) {
	inv := &invocation{}
	rest, err := parseRoot(inv, args)
	if err != nil || inv.showVersion {
		return inv, err
	}
	if wantsGeneralHelp(&rest) {
		inv.helpText = rootHelp()
		return inv, flag.ErrHelp
	}
	command, rest, err := findCommand(rest)
	if err != nil {
		return inv, err
	}
	inv.command = command
	return inv, parseCommand(inv, rest)
}

// wantsGeneralHelp is true for `help`, and for a command group (`secret`,
// `auth`) asked for help. `help <command>` becomes `<command> --help`, as in
// clap.
func wantsGeneralHelp(args *[]string) bool {
	words := *args
	if words[0] == "help" {
		if len(words) == 1 {
			return true
		}
		words = append(append([]string{}, words[1:]...), "--help")
		*args = words
	}
	isGroup := words[0] == "secret" || words[0] == "auth"
	return isGroup && len(words) == 2 && (words[1] == "--help" || words[1] == "-h")
}

func newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

// parseRoot reads the options before the command.
func parseRoot(inv *invocation, args []string) ([]string, error) {
	flags := newFlags("toolward")
	flags.StringVar(&inv.configPath, "config", "", configUsage)
	flags.BoolVar(&inv.showVersion, "version", false, "Print version")
	flags.BoolVar(&inv.showVersion, "V", false, "Print version")
	if err := flags.Parse(args); err != nil {
		return nil, rootError(inv, err)
	}
	if inv.showVersion {
		return nil, nil
	}
	if flags.NArg() == 0 {
		return nil, usageError("a command is required")
	}
	return flags.Args(), nil
}

func rootError(inv *invocation, err error) error {
	if errors.Is(err, flag.ErrHelp) {
		inv.helpText = rootHelp()
		return err
	}
	return usageError(err.Error())
}

func rootHelp() string {
	var text strings.Builder
	text.WriteString(about + "\n\nUsage: toolward [OPTIONS] <COMMAND>\n\nCommands:\n")
	for _, command := range commands {
		fmt.Fprintf(&text, "  %-14s %s\n", command.name, command.summary)
	}
	text.WriteString("\nOptions:\n  --config <PATH>  " + configUsage + "\n  -V, --version    Print version\n  -h, --help       Print help\n")
	return text.String()
}

// findCommand picks the command named by the first word, or the first two.
func findCommand(args []string) (*command, []string, error) {
	word := args[0]
	if word == "secret" || word == "auth" {
		return findSubcommand(word, args[1:])
	}
	for _, command := range commands {
		if command.name == word {
			return command, args[1:], nil
		}
	}
	return nil, nil, usageError(fmt.Sprintf("unrecognized subcommand '%s'", word))
}

func findSubcommand(group string, args []string) (*command, []string, error) {
	if len(args) == 0 {
		return nil, nil, usageError(fmt.Sprintf("'%s' needs a subcommand", group))
	}
	for _, command := range commands {
		if command.name == group+" "+args[0] {
			return command, args[1:], nil
		}
	}
	return nil, nil, usageError(fmt.Sprintf("unrecognized subcommand '%s %s'", group, args[0]))
}

// parseCommand reads the flags and arguments of one command. --config is also
// accepted here, and wins over the one before the command.
func parseCommand(inv *invocation, args []string) error {
	flags := newFlags(inv.command.name)
	flags.StringVar(&inv.configPath, "config", inv.configPath, configUsage)
	if inv.command.defineFlags != nil {
		inv.command.defineFlags(flags, inv)
	}
	arguments, err := parseInterspersed(flags, args)
	if errors.Is(err, flag.ErrHelp) {
		inv.helpText = commandHelp(inv.command, flags)
		return err
	}
	if err != nil {
		return usageError(err.Error())
	}
	return checkArguments(inv, arguments)
}

// parseInterspersed accepts flags before and after the arguments, as clap did.
func parseInterspersed(flags *flag.FlagSet, args []string) ([]string, error) {
	var arguments []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		rest := flags.Args()
		if len(rest) == 0 {
			return arguments, nil
		}
		if endedByDoubleDash(args, rest) {
			return append(arguments, rest...), nil
		}
		arguments = append(arguments, rest[0])
		args = rest[1:]
	}
}

func endedByDoubleDash(args, rest []string) bool {
	consumed := len(args) - len(rest)
	return consumed > 0 && args[consumed-1] == "--"
}

func checkArguments(inv *invocation, arguments []string) error {
	wanted := inv.command.positionals
	if len(arguments) < len(wanted) {
		return usageError(fmt.Sprintf("the required argument <%s> was not provided", strings.ToUpper(wanted[len(arguments)])))
	}
	if len(arguments) > len(wanted) {
		return usageError(fmt.Sprintf("unexpected argument '%s'", arguments[len(wanted)]))
	}
	inv.arguments = arguments
	return nil
}

func commandHelp(command *command, flags *flag.FlagSet) string {
	var text strings.Builder
	text.WriteString(command.summary + "\n\nUsage: toolward " + command.name)
	for _, name := range command.positionals {
		text.WriteString(" <" + strings.ToUpper(name) + ">")
	}
	text.WriteString(" [OPTIONS]\n\nOptions:\n")
	flags.VisitAll(func(f *flag.Flag) {
		fmt.Fprintf(&text, "  --%-10s %s\n", f.Name, f.Usage)
	})
	return text.String()
}

// argument returns the i-th argument.
func (inv *invocation) argument(i int) string {
	return inv.arguments[i]
}

// configPathOf is the config file: the flag, else the default location.
func configPathOf(inv *invocation) (string, error) {
	if inv.configPath != "" {
		return inv.configPath, nil
	}
	return config.DefaultPath()
}

func loadConfig(inv *invocation) (*config.Config, error) {
	path, err := configPathOf(inv)
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}
