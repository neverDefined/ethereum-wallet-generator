package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/glebarez/sqlite"
	"golang.org/x/term"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/planxnx/ethereum-wallet-generator/internal/encryption"
	"github.com/planxnx/ethereum-wallet-generator/internal/generators"
	"github.com/planxnx/ethereum-wallet-generator/internal/progressbar"
	"github.com/planxnx/ethereum-wallet-generator/internal/repository"
	"github.com/planxnx/ethereum-wallet-generator/utils"
	"github.com/planxnx/ethereum-wallet-generator/wallets"
)

func init() {
	if _, err := os.Stat("db"); os.IsNotExist(err) {
		if err := os.Mkdir("db", 0o750); err != nil {
			panic(err)
		}
	}
}

func main() {
	// Context with gracefully shutdown signal
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGHUP,  // kill -SIGHUP XXXX
		syscall.SIGINT,  // kill -SIGINT XXXX or Ctrl+c
		syscall.SIGQUIT, // kill -SIGQUIT XXXX
		syscall.SIGTERM, // kill -SIGTERM XXXX
	)
	defer stop()

	fmt.Println("===============ETH Wallet Generator===============")
	fmt.Println(" ")

	// Parse flags
	decryptFile := flag.String("decrypt", "", "decrypt encrypted JSON file (e.g., wallets.encrypted.json)")
	number := flag.Int("n", 10, "set number of generate times (not number of result wallets) (set number to -1 for Infinite loop ∞)")
	limit := flag.Int("limit", 0, "set limit number of result wallets. stop generate when result of vanity wallets reach the limit (set number to 0 for no limit)")
	dbPath := flag.String("db", "", "set sqlite output name eg. wallets.db (db file will create in /db)")
	concurrency := flag.Int("c", 1, "set concurrency value")
	bits := flag.Int("bit", 128, "set number of entropy bits [128, 256]")
	strict := flag.Bool("strict", false, "strict contains mode (required contains to use)")
	contain := flag.String("contains", "", "show only result that contained with the given letters (support for multiple characters)")
	prefix := flag.String("prefix", "", "show only result that prefix was matched with the given letters  (support for single character)")
	suffix := flag.String("suffix", "", "show only result that suffix was matched with the given letters (support for single character)")
	regEx := flag.String("regex", "", "show only result that was matched with given regex (eg. ^0x99 or ^0x00)")
	isDryrun := flag.Bool("dryrun", false, "generate wallet without a result (used for benchmark speed)")
	isCompatible := flag.Bool("compatible", false, "logging compatible mode (turn this on to fix logging glitch)")
	mode := flag.Int("mode", 1, "wallet generate mode [1: normal mode, 2: only private key mode(generate only privatekey, this fastest mode)]")
	flag.Parse()

	// Handle decrypt command
	if *decryptFile != "" {
		// Read encrypted file
		encryptedData, err := os.ReadFile(*decryptFile)
		if err != nil {
			log.Fatalf("Error reading encrypted file: %v", err)
		}

		// Prompt for password
		fmt.Print("Enter password to decrypt: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // newline after password input
		if err != nil {
			log.Fatalf("Error reading password: %v", err)
		}
		if len(password) == 0 {
			log.Fatal("Error: password cannot be empty")
		}

		// Decrypt
		decrypted, err := encryption.Decrypt(string(encryptedData), string(password))
		if err != nil {
			log.Fatalf("Error decrypting file: %v", err)
		}

		// Parse JSON to validate
		var wallets []*wallets.Wallet
		if err := json.Unmarshal([]byte(decrypted), &wallets); err != nil {
			log.Fatalf("Error parsing decrypted JSON: %v", err)
		}

		// Create output directory if it doesn't exist
		outputDir := "output"
		if err := os.MkdirAll(outputDir, 0750); err != nil {
			log.Fatalf("Error creating output directory: %v", err)
		}

		// Write decrypted JSON to output directory
		baseName := strings.TrimSuffix(filepath.Base(*decryptFile), ".encrypted.json")
		if baseName == filepath.Base(*decryptFile) {
			// If it doesn't have .encrypted.json suffix, just add .json
			baseName = strings.TrimSuffix(baseName, ".json")
		}
		outputFile := filepath.Join(outputDir, baseName+".json")
		if err := os.WriteFile(outputFile, []byte(decrypted), 0600); err != nil {
			log.Fatalf("Error writing decrypted file: %v", err)
		}

		fmt.Printf("Successfully decrypted %d wallets to %s\n", len(wallets), outputFile)
		return
	}

	// Wallet Address Validator
	r, err := regexp.Compile(*regEx)
	if err != nil {
		panic(err)
	}
	contains := strings.Split(*contain, ",")
	*prefix = utils.Add0xPrefix(*prefix)
	validateAddress := func(address string) bool {
		isValid := true
		if len(contains) > 0 {
			cb := func(contain string) bool {
				return strings.Contains(address, contain)
			}
			if *strict {
				if !utils.Have(contains, cb) {
					isValid = false
				}
			} else {
				if !utils.Some(contains, cb) {
					isValid = false
				}
			}
		}

		if *prefix != "" {
			if !strings.HasPrefix(address, *prefix) {
				isValid = false
			}
		}

		if *suffix != "" {
			if !strings.HasSuffix(address, *suffix) {
				isValid = false
			}
		}

		if *regEx != "" && !r.MatchString(address) {
			isValid = false
		}

		return isValid
	}
	if *number <= 0 {
		*number = -1
	}
	if *limit <= 0 {
		*limit = *number
	}

	// Progress bar
	var bar progressbar.ProgressBar
	if *isCompatible {
		bar = progressbar.NewCompatibleProgressBar(*number)
	} else {
		bar = progressbar.NewStandardProgressBar(*number)
	}

	// Repository
	var repo repository.Repository
	switch {
	case *dbPath != "":
		db, err := gorm.Open(sqlite.Open("./db/"+*dbPath), &gorm.Config{
			Logger:                 logger.Default.LogMode(logger.Silent),
			DryRun:                 *isDryrun,
			SkipDefaultTransaction: true,
		})
		if err != nil {
			panic(err)
		}

		defer func() {
			db, _ := db.DB()
			db.Close()
		}()

		if !*isDryrun {
			if err := db.AutoMigrate(&wallets.Wallet{}); err != nil {
				panic(err)
			}
		}

		repo = repository.NewGormRepository(db, uint64(*concurrency))
	default:
		repo = repository.NewInMemoryRepository()
	}

	// Wallet generator
	var walletGenerator wallets.Generator
	switch *mode {
	case 1:
		walletGenerator = wallets.NewGeneratorMnemonic(*bits)
	case 2:
		walletGenerator = wallets.NewGeneratorPrivatekey()
	default:
		panic("Invalid mode. See: https://github.com/Planxnx/ethereum-wallet-generator#Modes")
	}

	generator := generators.New(
		walletGenerator,
		repo,
		generators.Config{
			AddresValidator: validateAddress,
			ProgressBar:     bar,
			DryRun:          *isDryrun,
			Concurrency:     *concurrency,
			Number:          *number,
			Limit:           *limit,
		},
	)

	go func() {
		<-ctx.Done()

		if err := generator.Shutdown(); err != nil {
			log.Printf("Generator Shutdown Error: %+v", err)
		}

		if err := repo.Close(); err != nil {
			log.Printf("WalletsRepo Close Error: %+v", err)
		}
	}()

	if err := generator.Start(); err != nil {
		log.Printf("Generator Error: %+v", err)
	}
}
