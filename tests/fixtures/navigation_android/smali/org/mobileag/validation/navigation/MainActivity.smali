.class public Lorg/mobileag/validation/navigation/MainActivity;
.super Landroid/app/Activity;
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    const-string v0, "main"
    invoke-direct {p0, v0}, Lorg/mobileag/validation/navigation/MainActivity;->render(Ljava/lang/String;)V
    return-void
.end method
.method private render(Ljava/lang/String;)V
    .locals 3
    invoke-virtual {p0}, Landroid/app/Activity;->getResources()Landroid/content/res/Resources;
    move-result-object v0
    const-string v1, "layout"
    invoke-virtual {p0}, Landroid/app/Activity;->getPackageName()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v0, p1, v1, v2}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
    move-result v0
    invoke-virtual {p0, v0}, Landroid/app/Activity;->setContentView(I)V
    return-void
.end method
.method public onProfile(Landroid/view/View;)V
    .locals 1
    const-string v0, "profile"
    invoke-direct {p0, v0}, Lorg/mobileag/validation/navigation/MainActivity;->render(Ljava/lang/String;)V
    return-void
.end method
.method public onHome(Landroid/view/View;)V
    .locals 1
    const-string v0, "main"
    invoke-direct {p0, v0}, Lorg/mobileag/validation/navigation/MainActivity;->render(Ljava/lang/String;)V
    return-void
.end method
