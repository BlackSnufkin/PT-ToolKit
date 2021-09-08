Option Explicit
Dim oAppClass As New oAppClass
Public Sub AutoOpen()
ActiveDocument.Sections(1).Range.Font.Hidden = False
Set page1 = Selection.GoTo(What:=1, Which:=2, Name:=1).Bookmarks("\Page").Range
page1.Delete
Set oAppClass.oApp = Word.Application
End Sub
