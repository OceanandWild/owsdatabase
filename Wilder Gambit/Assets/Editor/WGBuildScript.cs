using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;
using WilderGambit.Editor;

/// <summary>
/// Build headless de Windows y Android para Wilder Gambit.
/// </summary>
public static class WGBuildScript
{
    private const string WindowsOutputDir = "Builds";
    private const string WindowsExeName = "Wilder Gambit.exe";

    private const string AndroidOutputDir = "Android Builds";
    private const string AndroidApkName = "wildergambit.apk";

    public static void BuildWindows()
    {
        BrandingSetup.Apply();
        BootSetup.CreateBootSceneForBuild();

        List<string> scenePaths = EditorBuildSettings.scenes
            .Where(scene => scene.enabled)
            .Select(scene => scene.path)
            .ToList();

        if (scenePaths.Count == 0)
        {
            throw new Exception("WGBuild: no hay escenas habilitadas en Build Settings.");
        }

        string outputPath = Path.Combine(WindowsOutputDir, WindowsExeName).Replace('\\', '/');
        Debug.Log("WGBuild: iniciando build Windows · escenas=" + scenePaths.Count + " · salida=" + outputPath);

        CleanDirectory(WindowsOutputDir);

        BuildPlayerOptions buildOptions = new BuildPlayerOptions
        {
            scenes = scenePaths.ToArray(),
            locationPathName = outputPath,
            target = BuildTarget.StandaloneWindows64,
            targetGroup = BuildTargetGroup.Standalone,
            options = BuildOptions.None
        };

        BuildReport report = BuildPipeline.BuildPlayer(buildOptions);
        BuildSummary summary = report.summary;

        Debug.Log("WGBuild: resultado=" + summary.result
                  + " · errores=" + summary.totalErrors
                  + " · warnings=" + summary.totalWarnings
                  + " · tamano=" + summary.totalSize + " bytes"
                  + " · salida=" + outputPath);

        if (summary.result != BuildResult.Succeeded)
        {
            throw new Exception("WGBuild: build fallido (resultado=" + summary.result
                                + ", errores=" + summary.totalErrors + "). Revisar log de Unity.");
        }

        Debug.Log("WGBuild: BUILD OK");
    }

    public static void BuildAndroid()
    {
        BrandingSetup.Apply();
        BootSetup.CreateBootSceneForBuild();

        // Firma con el keystore oficial del proyecto (no rotar).
        string keystorePath = @"C:\Users\Equipo\Desktop\OWS Unity\secrets\wilder-gambit\wilder-gambit.keystore";
        string keystorePass = File.ReadAllText(@"C:\Users\Equipo\Desktop\OWS Unity\secrets\wilder-gambit\keystore.pass.txt").Trim();
        if (string.IsNullOrWhiteSpace(keystorePass))
        {
            throw new Exception("WGBuild Android: no se pudo leer la clave del keystore.");
        }

        PlayerSettings.Android.useCustomKeystore = true;
        PlayerSettings.Android.keystoreName = keystorePath;
        PlayerSettings.Android.keyaliasName = "wildergambit";
        PlayerSettings.Android.keystorePass = keystorePass;
        PlayerSettings.Android.keyaliasPass = keystorePass;
        PlayerSettings.SetScriptingBackend(NamedBuildTarget.Android, ScriptingImplementation.IL2CPP);
        PlayerSettings.Android.targetArchitectures = AndroidArchitecture.ARM64;

        List<string> scenePaths = EditorBuildSettings.scenes
            .Where(scene => scene.enabled)
            .Select(scene => scene.path)
            .ToList();

        if (scenePaths.Count == 0)
        {
            throw new Exception("WGBuild: no hay escenas habilitadas en Build Settings.");
        }

        if (!Directory.Exists(AndroidOutputDir))
        {
            Directory.CreateDirectory(AndroidOutputDir);
        }
        string outputPath = Path.Combine(AndroidOutputDir, AndroidApkName).Replace('\\', '/');
        Debug.Log("WGBuild: iniciando build Android · escenas=" + scenePaths.Count + " · salida=" + outputPath);

        string apkPath = Path.Combine(AndroidOutputDir, AndroidApkName);
        if (File.Exists(apkPath)) { File.Delete(apkPath); }

        BuildPlayerOptions buildOptions = new BuildPlayerOptions
        {
            scenes = scenePaths.ToArray(),
            locationPathName = outputPath,
            target = BuildTarget.Android,
            targetGroup = BuildTargetGroup.Android,
            options = BuildOptions.None
        };

        BuildReport report = BuildPipeline.BuildPlayer(buildOptions);
        BuildSummary summary = report.summary;

        Debug.Log("WGBuild: resultado=" + summary.result
                  + " · errores=" + summary.totalErrors
                  + " · warnings=" + summary.totalWarnings
                  + " · tamano=" + summary.totalSize + " bytes"
                  + " · salida=" + outputPath);

        if (summary.result != BuildResult.Succeeded)
        {
            throw new Exception("WGBuild: build Android fallido (resultado=" + summary.result
                                + ", errores=" + summary.totalErrors + "). Revisar log de Unity.");
        }

        Debug.Log("WGBuild: BUILD ANDROID OK");
    }

    private static void CleanDirectory(string dir)
    {
        if (!Directory.Exists(dir))
        {
            return;
        }

        foreach (string file in Directory.GetFiles(dir))
        {
            try { File.Delete(file); }
            catch (Exception e) { Debug.LogWarning("WGBuild: no se pudo borrar " + file + " (" + e.Message + ")"); }
        }

        foreach (string d in Directory.GetDirectories(dir))
        {
            try { Directory.Delete(d, true); }
            catch (Exception e) { Debug.LogWarning("WGBuild: no se pudo borrar " + d + " (" + e.Message + ")"); }
        }
    }
}