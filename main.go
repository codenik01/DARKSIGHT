package main

import (
	_ "embed"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"surface-intel/pkg/ai"
	"surface-intel/pkg/api"
	"surface-intel/pkg/db"
	"surface-intel/pkg/models"
	"surface-intel/pkg/runner"
)

//go:embed web/index.html
var embeddedIndexHTML []byte

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Global DB initialization
	store, err := db.NewStore("")
	if err != nil {
		fmt.Printf("[-] Database error: %v\n", err)
		os.Exit(1)
	}

	aiClient := ai.NewAIClient()
	toolRunner := runner.NewToolRunner(models.ToolConfig{})
	orchestrator := runner.NewPipelineOrchestrator(store, toolRunner, aiClient)

	switch command {
	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		port := serveCmd.Int("port", 8080, "Web dashboard HTTP port")
		_ = serveCmd.Parse(os.Args[2:])

		server := api.NewServer(store, orchestrator, aiClient, *port)
		if err := server.Start(embeddedIndexHTML); err != nil {
			fmt.Printf("[-] Server error: %v\n", err)
			os.Exit(1)
		}

	case "scan", "run":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		targetDomain := scanCmd.String("t", "", "Target domain (e.g., example.com)")
		workflow := scanCmd.String("workflow", "full", "Pipeline workflow (full|fast)")
		_ = scanCmd.Parse(os.Args[2:])

		if *targetDomain == "" {
			fmt.Println("[-] Error: -t target domain is required.")
			scanCmd.Usage()
			os.Exit(1)
		}

		fmt.Printf("[*] Launching Darksight Autonomous Pipeline for target domain: %s\n", *targetDomain)

		eventSub := orchestrator.Subscribe()
		go func() {
			for ev := range eventSub {
				fmt.Printf("[%s] [%s] %s\n", ev.Stage, ev.Level, ev.Message)
			}
		}()

		ctx := context.Background()
		run, err := orchestrator.ExecuteRun(ctx, *targetDomain, *workflow)
		if err != nil {
			fmt.Printf("[-] Scan failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n[+] Scan Completed! Run ID: %s | Subdomains: %d | Services: %d | Endpoints: %d | Findings: %d\n",
			run.ID, run.TotalSubdomains, run.TotalServices, run.TotalEndpoints, run.TotalFindings)

	case "memory":
		mem := orchestrator.GetExperienceDB()
		stats := mem.Stats()
		fmt.Println("==================================================")
		fmt.Println("           DARKSIGHT EXPERIENCE DB (4-TIER)")
		fmt.Println("==================================================")
		fmt.Printf("Confirmed Findings Memory:  %v\n", stats["total_confirmed_findings"])
		fmt.Printf("Failure / Lesson Memory:    %v\n", stats["total_failure_lessons"])
		fmt.Printf("Active Strategic Patterns:  %v\n", stats["active_strategies"])
		fmt.Printf("Tool Contexts Tracked:      %v\n", stats["tool_contexts_tracked"])

		fmt.Println("\n--- Strategy Memory (Learned Weights & Success Rates) ---")
		for _, s := range mem.Strategies {
			fmt.Printf("• [%s] Hypothesis: %s\n", s.Context, s.Hypothesis)
			fmt.Printf("  Action:       %s\n", s.BestAction)
			fmt.Printf("  Success Rate: %.1f%% (Trials: %d | Confirmed: %d | FP: %d)\n\n", s.SuccessRate, s.TrialsCount, s.ConfirmedCount, s.FalsePositiveCount)
		}

		fmt.Println("--- Failure Memory (Lessons Learned & FP Prevention) ---")
		if len(mem.Failures) == 0 {
			fmt.Println("  (No false positive failures recorded yet)")
		} else {
			for _, f := range mem.Failures {
				fmt.Printf("• Thought:  %s\n", f.WhatAIThought)
				fmt.Printf("  Why Wrong: %s\n", f.WhyWasItWrong)
				fmt.Printf("  Lesson:    %s\n\n", f.LessonLearned)
			}
		}

	case "export":
		exportCmd := flag.NewFlagSet("export", flag.ExitOnError)
		targetDomain := exportCmd.String("t", "", "Target domain")
		outputFile := exportCmd.String("o", "darksight-export.json", "Output JSON path")
		_ = exportCmd.Parse(os.Args[2:])

		if *targetDomain == "" {
			fmt.Println("[-] Error: -t target domain is required.")
			os.Exit(1)
		}

		target, err := store.GetTargetByDomain(*targetDomain)
		if err != nil {
			fmt.Printf("[-] Target domain %s not found in database.\n", *targetDomain)
			os.Exit(1)
		}

		subs, _ := store.ListSubdomains(target.ID)
		svcs, _ := store.ListHTTPServices(target.ID)
		eps, _ := store.ListEndpoints(target.ID)
		fnds, _ := store.ListFindings(target.ID)

		exportData := map[string]interface{}{
			"target":     target,
			"subdomains": subs,
			"services":   svcs,
			"endpoints":  eps,
			"findings":   fnds,
		}

		bytes, _ := json.MarshalIndent(exportData, "", "  ")
		if err := os.WriteFile(*outputFile, bytes, 0644); err != nil {
			fmt.Printf("[-] Failed to write export file: %v\n", err)
			os.Exit(1)
		}

		absPath, _ := filepath.Abs(*outputFile)
		fmt.Printf("[+] Successfully exported surface intelligence data to %s\n", absPath)

	case "status":
		stats, err := store.GetStats()
		if err != nil {
			fmt.Printf("[-] Error fetching stats: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("=== Darksight Threat Surface Intelligence Summary ===")
		fmt.Printf("Total Targets:     %v\n", stats["targets"])
		fmt.Printf("Total Subdomains:  %v\n", stats["subdomains"])
		fmt.Printf("HTTP Services:     %v\n", stats["services"])
		fmt.Printf("API Endpoints:     %v\n", stats["endpoints"])
		fmt.Printf("Security Findings: %v\n", stats["findings"])

	case "clear":
		if err := store.ClearAllData(); err != nil {
			fmt.Printf("[-] Failed to clear database: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Successfully wiped all historical records and database tables.")

	case "delete":
		delCmd := flag.NewFlagSet("delete", flag.ExitOnError)
		targetDomain := delCmd.String("t", "", "Target domain to delete")
		_ = delCmd.Parse(os.Args[2:])

		if *targetDomain == "" {
			fmt.Println("[-] Error: -t target domain is required.")
			os.Exit(1)
		}

		target, err := store.GetTargetByDomain(*targetDomain)
		if err != nil {
			fmt.Printf("[-] Target %s not found in database.\n", *targetDomain)
			os.Exit(1)
		}

		if err := store.DeleteTarget(target.ID); err != nil {
			fmt.Printf("[-] Error deleting target: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Target %s and all associated assets successfully deleted.\n", *targetDomain)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Darksight - Autonomous Attack Surface Intelligence & Vulnerability Engine

Usage:
  darksight <command> [flags]

Commands:
  run / scan - Execute autonomous recon & verification loop (e.g. darksight run -t example.com)
  serve      - Start local tactical web console (e.g. darksight serve --port 8080)
  memory     - Inspect 4-tier Experience DB (strategies, success rates, failure lessons)
  export     - Export intelligence telemetry to JSON (e.g. darksight export -t example.com)
  status     - Print threat surface database statistics
  delete     - Delete specific target records (e.g. darksight delete -t example.com)
  clear      - Purge all targets, assets, and findings history from database`)
}
