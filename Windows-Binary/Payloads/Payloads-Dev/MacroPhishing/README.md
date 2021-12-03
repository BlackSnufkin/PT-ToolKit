# MacroPhishing
Word resources for phishing with macros. Includes "Click Enable Content" bait and decoy document deployment. The bait was created by me, but inspired by cerber ransomware document samples. 

# Usage

To use, open template.doc and create new macros. For the main module, paste in the code from main.vba. Then create a new Class Module named "oAppClass" or rename it to whatever, but make sure the name matches that in the main module. Paste in the code from oAppClass.vba. Add in your code to run your malware. For the decoy, put in your decoy text in the "Decoy goes here in hidden text." section. After setting the text to hidden, the second page should go away, leaving the bait. Then, select all of the decoy text, and set the font to hidden. This hides it from the user when the macro is not executed. When the macro runs, it deletes the first page (the bait), and unhides all text (displays the decoy). Then, it automatically chooses not to save the changes, so that the user does not get the "would you like to save" prompt, and the macro doesn't delete the decoy after future views. This all happens smoothly and does not require downloading or opening new instances of word. By default, once macros have been enabled for the document, it will automatically run when opened again. This has the same visual effect as if it only contains the decoy. 

# Demo

![Demo](https://github.com/TheKevinWang/MacroPhishing/raw/master/WordMacroDemo.gif)
