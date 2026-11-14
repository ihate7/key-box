using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using FormsTimer = System.Windows.Forms.Timer;

namespace KeyBox.UI
{
    internal enum ClipboardEvent
    {
        Copied,
        Countdown,
        Cleared,
        Replaced
    }

    internal sealed class ClipboardEventArgs : EventArgs
    {
        public ClipboardEventArgs(ClipboardEvent kind)
        {
            Kind = kind;
        }

        public ClipboardEvent Kind { get; private set; }
    }

    /// <summary>
    /// Копирование секретов в буфер обмена с автоматической очисткой.
    /// Значение помечается так, чтобы Windows не сохраняла его в журнале буфера (Win+V)
    /// и не синхронизировала с облаком. Через заданное время буфер очищается — но только
    /// если в нём всё ещё лежит то, что положили мы. Таймер живёт и при заблокированном
    /// хранилище; при выходе из программы буфер тоже очищается.
    /// </summary>
    internal static class ClipboardGuard
    {
        private static FormsTimer timer;
        private static uint ownedSequence;
        private static bool pending;
        private static int secondsLeft;
        private static string label = "";

        public static event EventHandler<ClipboardEventArgs> Changed;

        /// <summary>true, пока в буфере лежит скопированное нами значение и идёт отсчёт.</summary>
        public static bool Pending
        {
            get { return pending; }
        }

        public static int SecondsLeft
        {
            get { return secondsLeft; }
        }

        /// <summary>Что было скопировано: «Пароль» или «Логин».</summary>
        public static string Label
        {
            get { return label; }
        }

        public static bool Copy(string text, string what, int clearAfterSeconds)
        {
            try
            {
                var data = new DataObject();
                data.SetData(DataFormats.UnicodeText, true, text);
                data.SetData("ExcludeClipboardContentFromMonitorProcessing", false, new MemoryStream(new byte[] { 1, 0, 0, 0 }));
                data.SetData("CanIncludeInClipboardHistory", false, new MemoryStream(new byte[4]));
                data.SetData("CanUploadToCloudClipboard", false, new MemoryStream(new byte[4]));
                Clipboard.SetDataObject(data, true, 5, 100);
            }
            catch (ExternalException)
            {
                return false;
            }

            ownedSequence = NativeMethods.GetClipboardSequenceNumber();
            pending = true;
            secondsLeft = clearAfterSeconds;
            label = what;

            if (timer == null)
            {
                timer = new FormsTimer();
                timer.Interval = 1000;
                timer.Tick += OnTick;
            }
            timer.Start();
            Raise(ClipboardEvent.Copied);
            return true;
        }

        /// <summary>Очищает буфер обмена, если в нём всё ещё наше значение.</summary>
        public static void ClearIfOwned()
        {
            if (!pending) return;
            Stop();

            bool cleared = false;
            try
            {
                if (NativeMethods.GetClipboardSequenceNumber() == ownedSequence)
                {
                    Clipboard.Clear();
                    cleared = true;
                }
            }
            catch (ExternalException) { }

            Raise(cleared ? ClipboardEvent.Cleared : ClipboardEvent.Replaced);
        }

        private static void OnTick(object sender, EventArgs e)
        {
            if (!pending)
            {
                Stop();
                return;
            }
            if (NativeMethods.GetClipboardSequenceNumber() != ownedSequence)
            {
                // В буфер уже скопировали что-то другое — чужое не трогаем.
                Stop();
                Raise(ClipboardEvent.Replaced);
                return;
            }

            secondsLeft--;
            if (secondsLeft <= 0)
            {
                ClearIfOwned();
            }
            else
            {
                Raise(ClipboardEvent.Countdown);
            }
        }

        private static void Stop()
        {
            pending = false;
            secondsLeft = 0;
            if (timer != null) timer.Stop();
        }

        private static void Raise(ClipboardEvent kind)
        {
            EventHandler<ClipboardEventArgs> handler = Changed;
            if (handler != null) handler(null, new ClipboardEventArgs(kind));
        }
    }
}
