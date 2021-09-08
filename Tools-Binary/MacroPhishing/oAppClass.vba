Option Explicit
Public WithEvents oApp As Word.Application
Private Sub oApp_DocumentBeforeClose(ByVal Doc As Document, Cancel As Boolean)
Cancel = True
Application.Quit SaveChanges:=wdDoNotSaveChanges
End Sub
