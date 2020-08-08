package main

import (
	"fmt"
	"github.com/c-bata/go-prompt"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

var transactions map[string]*engine.Transaction
var selectedTransaction string
var waf *engine.Waf

func homeCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "transactions", Description: "Store the username and age"},
		{Text: "load", Description: "Loads a config file, must be absolute path."},
		{Text: "redis", Description: "Store the text commented to articles"},
		{Text: "help", Description: "Store the text commented to articles"},
		{Text: "exit", Description: "Store the text commented to articles"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func txListCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "new", Description: "Store the username and age"},
		{Text: "back", Description: "Go back to the main menu"},
		{Text: "exit", Description: "Go back to the main menu"},
	}
	for id, _ := range transactions{
		sugg := prompt.Suggest{Text: id, Description: "Transaction timestamp"}
		s = append(s, sugg)
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func txCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "phase", Description: "Evaluates selected phase (1-5)"},
		{Text: "rule", Description: "Evaluate the specified rule ID"},
		{Text: "dump", Description: "Displays every stored variable for the transaction"},
		{Text: "destroy", Description: "Destroy curren transaction"},
		{Text: "expand", Description: "Get macro expansion result"},
		{Text: "get", Description: "Get variable, supports ARGS:/regex/ syntax"},
		{Text: "set", Description: "Sets a variable, syntax: set [collection] [key] [index] [value], key and index are optional"},
		{Text: "log", Description: "Dumps audit log"},
		{Text: "back", Description: "Back to transaction selection"},
		{Text: "exit", Description: "Exit program"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func transaction(id string){
	tx := transactions[id]
	if tx == nil{
		fmt.Println("Invalid transaction ID")
		txlist()
		return
	}
	fmt.Println("Select on action.")
	t := prompt.Input("> ", txCompleter)
	switch(t){
	case "dump":
		for col, cdata := range tx.Collections{
			fmt.Printf("------ %s ------\n", col)
			for key, d := range cdata.Data{
				if key != ""{
					fmt.Printf("%s:\n", key)
				}
				for i, val := range d{
					fmt.Printf("%d. %s\n", i, val)
				}
			}
		}
		transaction(id)
	case "back":
		txlist()
	default:
		fmt.Println("Invalid action.")
		transaction(id)
	}
}

func txlist(){
	fmt.Println("Select or create a transaction.")
	t := prompt.Input("> ", txListCompleter)
	switch t{
	case "new":
		tx := waf.NewTransaction()
		transactions[tx.Id] = tx
		fmt.Println("Transaction created with ID", tx.Id)
		transaction(tx.Id)
	case "list":
		for txid, _ := range transactions{
			fmt.Println(txid)
		}
		txlist()
	case "back":
		home()
	default:
		if transactions[t] != nil{
			fmt.Println("Selected transaction", t)
			transaction(t)
			return
		}
		fmt.Println("Invalid action or transaction id.")
		txlist()
	}
}

func home(){
	transactions = map[string]*engine.Transaction{}
	waf = &engine.Waf{}
	waf.Init()
	fmt.Println("Please select a module.")
	t := prompt.Input("> ", homeCompleter)
	switch t{
	case "transactions":
		txlist()
	case "exit":
		return
	default:
		fmt.Println("Invalid command.")
		home()
	}
}

func main() {
	home()
	fmt.Println("Exiting debug console...")
}