using SharpDX.DirectInput;
using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace KeyboardInputsAPI
{
    public class KeyboardInput
    {
        [DllImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
        private static extern uint TimeBeginPeriod(uint ms);
        [DllImport("winmm.dll", EntryPoint = "timeEndPeriod")]
        private static extern uint TimeEndPeriod(uint ms);
        [DllImport("ntdll.dll", EntryPoint = "NtSetTimerResolution")]
        private static extern void NtSetTimerResolution(uint DesiredResolution, bool SetResolution, ref uint CurrentResolution);
        private static uint CurrentResolution = 0;
        private bool running;
        DirectInput directInput = new DirectInput();
        private int number;
        public KeyboardInput()
        {
            TimeBeginPeriod(1);
            NtSetTimerResolution(1, true, ref CurrentResolution);
            running = true;
        }
        public void Close()
        {
            running = false;
        }
        public void taskK()
        {
            for (; ; )
            {
                if (!running)
                    break;
                ProcessStateLogic();
                System.Threading.Thread.Sleep(1);
            }
        }
        public void BeginPolling()
        {
            Task.Run(() => taskK());
        }
        private Keyboard[] keyboard = new Keyboard[] { null, null, null, null };
        private Guid[] keyboardGuid = new Guid[] { Guid.Empty, Guid.Empty, Guid.Empty, Guid.Empty };
        private int knum = 0;
        public bool KeyboardKeyEscape;
        public bool KeyboardKeyD1;
        public bool KeyboardKeyD2;
        public bool KeyboardKeyD3;
        public bool KeyboardKeyD4;
        public bool KeyboardKeyD5;
        public bool KeyboardKeyD6;
        public bool KeyboardKeyD7;
        public bool KeyboardKeyD8;
        public bool KeyboardKeyD9;
        public bool KeyboardKeyD0;
        public bool KeyboardKeyMinus;
        public bool KeyboardKeyEquals;
        public bool KeyboardKeyBack;
        public bool KeyboardKeyTab;
        public bool KeyboardKeyQ;
        public bool KeyboardKeyW;
        public bool KeyboardKeyE;
        public bool KeyboardKeyR;
        public bool KeyboardKeyT;
        public bool KeyboardKeyY;
        public bool KeyboardKeyU;
        public bool KeyboardKeyI;
        public bool KeyboardKeyO;
        public bool KeyboardKeyP;
        public bool KeyboardKeyLeftBracket;
        public bool KeyboardKeyRightBracket;
        public bool KeyboardKeyReturn;
        public bool KeyboardKeyLeftControl;
        public bool KeyboardKeyA;
        public bool KeyboardKeyS;
        public bool KeyboardKeyD;
        public bool KeyboardKeyF;
        public bool KeyboardKeyG;
        public bool KeyboardKeyH;
        public bool KeyboardKeyJ;
        public bool KeyboardKeyK;
        public bool KeyboardKeyL;
        public bool KeyboardKeySemicolon;
        public bool KeyboardKeyApostrophe;
        public bool KeyboardKeyGrave;
        public bool KeyboardKeyLeftShift;
        public bool KeyboardKeyBackslash;
        public bool KeyboardKeyZ;
        public bool KeyboardKeyX;
        public bool KeyboardKeyC;
        public bool KeyboardKeyV;
        public bool KeyboardKeyB;
        public bool KeyboardKeyN;
        public bool KeyboardKeyM;
        public bool KeyboardKeyComma;
        public bool KeyboardKeyPeriod;
        public bool KeyboardKeySlash;
        public bool KeyboardKeyRightShift;
        public bool KeyboardKeyMultiply;
        public bool KeyboardKeyLeftAlt;
        public bool KeyboardKeySpace;
        public bool KeyboardKeyCapital;
        public bool KeyboardKeyF1;
        public bool KeyboardKeyF2;
        public bool KeyboardKeyF3;
        public bool KeyboardKeyF4;
        public bool KeyboardKeyF5;
        public bool KeyboardKeyF6;
        public bool KeyboardKeyF7;
        public bool KeyboardKeyF8;
        public bool KeyboardKeyF9;
        public bool KeyboardKeyF10;
        public bool KeyboardKeyNumberLock;
        public bool KeyboardKeyScrollLock;
        public bool KeyboardKeyNumberPad7;
        public bool KeyboardKeyNumberPad8;
        public bool KeyboardKeyNumberPad9;
        public bool KeyboardKeySubtract;
        public bool KeyboardKeyNumberPad4;
        public bool KeyboardKeyNumberPad5;
        public bool KeyboardKeyNumberPad6;
        public bool KeyboardKeyAdd;
        public bool KeyboardKeyNumberPad1;
        public bool KeyboardKeyNumberPad2;
        public bool KeyboardKeyNumberPad3;
        public bool KeyboardKeyNumberPad0;
        public bool KeyboardKeyDecimal;
        public bool KeyboardKeyOem102;
        public bool KeyboardKeyF11;
        public bool KeyboardKeyF12;
        public bool KeyboardKeyF13;
        public bool KeyboardKeyF14;
        public bool KeyboardKeyF15;
        public bool KeyboardKeyKana;
        public bool KeyboardKeyAbntC1;
        public bool KeyboardKeyConvert;
        public bool KeyboardKeyNoConvert;
        public bool KeyboardKeyYen;
        public bool KeyboardKeyAbntC2;
        public bool KeyboardKeyNumberPadEquals;
        public bool KeyboardKeyPreviousTrack;
        public bool KeyboardKeyAT;
        public bool KeyboardKeyColon;
        public bool KeyboardKeyUnderline;
        public bool KeyboardKeyKanji;
        public bool KeyboardKeyStop;
        public bool KeyboardKeyAX;
        public bool KeyboardKeyUnlabeled;
        public bool KeyboardKeyNextTrack;
        public bool KeyboardKeyNumberPadEnter;
        public bool KeyboardKeyRightControl;
        public bool KeyboardKeyMute;
        public bool KeyboardKeyCalculator;
        public bool KeyboardKeyPlayPause;
        public bool KeyboardKeyMediaStop;
        public bool KeyboardKeyVolumeDown;
        public bool KeyboardKeyVolumeUp;
        public bool KeyboardKeyWebHome;
        public bool KeyboardKeyNumberPadComma;
        public bool KeyboardKeyDivide;
        public bool KeyboardKeyPrintScreen;
        public bool KeyboardKeyRightAlt;
        public bool KeyboardKeyPause;
        public bool KeyboardKeyHome;
        public bool KeyboardKeyUp;
        public bool KeyboardKeyPageUp;
        public bool KeyboardKeyLeft;
        public bool KeyboardKeyRight;
        public bool KeyboardKeyEnd;
        public bool KeyboardKeyDown;
        public bool KeyboardKeyPageDown;
        public bool KeyboardKeyInsert;
        public bool KeyboardKeyDelete;
        public bool KeyboardKeyLeftWindowsKey;
        public bool KeyboardKeyRightWindowsKey;
        public bool KeyboardKeyApplications;
        public bool KeyboardKeyPower;
        public bool KeyboardKeySleep;
        public bool KeyboardKeyWake;
        public bool KeyboardKeyWebSearch;
        public bool KeyboardKeyWebFavorites;
        public bool KeyboardKeyWebRefresh;
        public bool KeyboardKeyWebStop;
        public bool KeyboardKeyWebForward;
        public bool KeyboardKeyWebBack;
        public bool KeyboardKeyMyComputer;
        public bool KeyboardKeyMail;
        public bool KeyboardKeyMediaSelect;
        public bool KeyboardKeyUnknown;
        public bool Scan(int number = 0)
        {
            try
            {
                this.number = number;
                directInput = new DirectInput();
                keyboard = new Keyboard[] { null, null, null, null };
                keyboardGuid = new Guid[] { Guid.Empty, Guid.Empty, Guid.Empty, Guid.Empty };
                knum = 0;
                foreach (var deviceInstance in directInput.GetDevices(SharpDX.DirectInput.DeviceType.Keyboard, DeviceEnumerationFlags.AllDevices))
                {
                    keyboardGuid[knum] = deviceInstance.InstanceGuid;
                    knum++;
                }
            }
            catch { }
            if (keyboardGuid[0] == Guid.Empty)
            {
                return false;
            }
            else
            {
                int inc = number < 2 ? 0 : number - 1;
                keyboard[inc] = new Keyboard(directInput);
                keyboard[inc].Properties.BufferSize = 128;
                keyboard[inc].Acquire();
                return true;
            }
        }
        public void ProcessStateLogic()
        {
            int inc = number < 2 ? 0 : number - 1;
            keyboard[inc].Poll();
            var datas = keyboard[inc].GetBufferedData();
            foreach (var state in datas)
            {
                if (state.IsPressed & state.Key == Key.Escape)
                    KeyboardKeyEscape = true;
                if (state.IsReleased & state.Key == Key.Escape)
                    KeyboardKeyEscape = false;
                if (state.IsPressed & state.Key == Key.D1)
                    KeyboardKeyD1 = true;
                if (state.IsReleased & state.Key == Key.D1)
                    KeyboardKeyD1 = false;
                if (state.IsPressed & state.Key == Key.D2)
                    KeyboardKeyD2 = true;
                if (state.IsReleased & state.Key == Key.D2)
                    KeyboardKeyD2 = false;
                if (state.IsPressed & state.Key == Key.D3)
                    KeyboardKeyD3 = true;
                if (state.IsReleased & state.Key == Key.D3)
                    KeyboardKeyD3 = false;
                if (state.IsPressed & state.Key == Key.D4)
                    KeyboardKeyD4 = true;
                if (state.IsReleased & state.Key == Key.D4)
                    KeyboardKeyD4 = false;
                if (state.IsPressed & state.Key == Key.D5)
                    KeyboardKeyD5 = true;
                if (state.IsReleased & state.Key == Key.D5)
                    KeyboardKeyD5 = false;
                if (state.IsPressed & state.Key == Key.D6)
                    KeyboardKeyD6 = true;
                if (state.IsReleased & state.Key == Key.D6)
                    KeyboardKeyD6 = false;
                if (state.IsPressed & state.Key == Key.D7)
                    KeyboardKeyD7 = true;
                if (state.IsReleased & state.Key == Key.D7)
                    KeyboardKeyD7 = false;
                if (state.IsPressed & state.Key == Key.D8)
                    KeyboardKeyD8 = true;
                if (state.IsReleased & state.Key == Key.D8)
                    KeyboardKeyD8 = false;
                if (state.IsPressed & state.Key == Key.D9)
                    KeyboardKeyD9 = true;
                if (state.IsReleased & state.Key == Key.D9)
                    KeyboardKeyD9 = false;
                if (state.IsPressed & state.Key == Key.D0)
                    KeyboardKeyD0 = true;
                if (state.IsReleased & state.Key == Key.D0)
                    KeyboardKeyD0 = false;
                if (state.IsPressed & state.Key == Key.Minus)
                    KeyboardKeyMinus = true;
                if (state.IsReleased & state.Key == Key.Minus)
                    KeyboardKeyMinus = false;
                if (state.IsPressed & state.Key == Key.Equals)
                    KeyboardKeyEquals = true;
                if (state.IsReleased & state.Key == Key.Equals)
                    KeyboardKeyEquals = false;
                if (state.IsPressed & state.Key == Key.Back)
                    KeyboardKeyBack = true;
                if (state.IsReleased & state.Key == Key.Back)
                    KeyboardKeyBack = false;
                if (state.IsPressed & state.Key == Key.Tab)
                    KeyboardKeyTab = true;
                if (state.IsReleased & state.Key == Key.Tab)
                    KeyboardKeyTab = false;
                if (state.IsPressed & state.Key == Key.Q)
                    KeyboardKeyQ = true;
                if (state.IsReleased & state.Key == Key.Q)
                    KeyboardKeyQ = false;
                if (state.IsPressed & state.Key == Key.W)
                    KeyboardKeyW = true;
                if (state.IsReleased & state.Key == Key.W)
                    KeyboardKeyW = false;
                if (state.IsPressed & state.Key == Key.E)
                    KeyboardKeyE = true;
                if (state.IsReleased & state.Key == Key.E)
                    KeyboardKeyE = false;
                if (state.IsPressed & state.Key == Key.R)
                    KeyboardKeyR = true;
                if (state.IsReleased & state.Key == Key.R)
                    KeyboardKeyR = false;
                if (state.IsPressed & state.Key == Key.T)
                    KeyboardKeyT = true;
                if (state.IsReleased & state.Key == Key.T)
                    KeyboardKeyT = false;
                if (state.IsPressed & state.Key == Key.Y)
                    KeyboardKeyY = true;
                if (state.IsReleased & state.Key == Key.Y)
                    KeyboardKeyY = false;
                if (state.IsPressed & state.Key == Key.U)
                    KeyboardKeyU = true;
                if (state.IsReleased & state.Key == Key.U)
                    KeyboardKeyU = false;
                if (state.IsPressed & state.Key == Key.I)
                    KeyboardKeyI = true;
                if (state.IsReleased & state.Key == Key.I)
                    KeyboardKeyI = false;
                if (state.IsPressed & state.Key == Key.O)
                    KeyboardKeyO = true;
                if (state.IsReleased & state.Key == Key.O)
                    KeyboardKeyO = false;
                if (state.IsPressed & state.Key == Key.P)
                    KeyboardKeyP = true;
                if (state.IsReleased & state.Key == Key.P)
                    KeyboardKeyP = false;
                if (state.IsPressed & state.Key == Key.LeftBracket)
                    KeyboardKeyLeftBracket = true;
                if (state.IsReleased & state.Key == Key.LeftBracket)
                    KeyboardKeyLeftBracket = false;
                if (state.IsPressed & state.Key == Key.RightBracket)
                    KeyboardKeyRightBracket = true;
                if (state.IsReleased & state.Key == Key.RightBracket)
                    KeyboardKeyRightBracket = false;
                if (state.IsPressed & state.Key == Key.Return)
                    KeyboardKeyReturn = true;
                if (state.IsReleased & state.Key == Key.Return)
                    KeyboardKeyReturn = false;
                if (state.IsPressed & state.Key == Key.LeftControl)
                    KeyboardKeyLeftControl = true;
                if (state.IsReleased & state.Key == Key.LeftControl)
                    KeyboardKeyLeftControl = false;
                if (state.IsPressed & state.Key == Key.A)
                    KeyboardKeyA = true;
                if (state.IsReleased & state.Key == Key.A)
                    KeyboardKeyA = false;
                if (state.IsPressed & state.Key == Key.S)
                    KeyboardKeyS = true;
                if (state.IsReleased & state.Key == Key.S)
                    KeyboardKeyS = false;
                if (state.IsPressed & state.Key == Key.D)
                    KeyboardKeyD = true;
                if (state.IsReleased & state.Key == Key.D)
                    KeyboardKeyD = false;
                if (state.IsPressed & state.Key == Key.F)
                    KeyboardKeyF = true;
                if (state.IsReleased & state.Key == Key.F)
                    KeyboardKeyF = false;
                if (state.IsPressed & state.Key == Key.G)
                    KeyboardKeyG = true;
                if (state.IsReleased & state.Key == Key.G)
                    KeyboardKeyG = false;
                if (state.IsPressed & state.Key == Key.H)
                    KeyboardKeyH = true;
                if (state.IsReleased & state.Key == Key.H)
                    KeyboardKeyH = false;
                if (state.IsPressed & state.Key == Key.J)
                    KeyboardKeyJ = true;
                if (state.IsReleased & state.Key == Key.J)
                    KeyboardKeyJ = false;
                if (state.IsPressed & state.Key == Key.K)
                    KeyboardKeyK = true;
                if (state.IsReleased & state.Key == Key.K)
                    KeyboardKeyK = false;
                if (state.IsPressed & state.Key == Key.L)
                    KeyboardKeyL = true;
                if (state.IsReleased & state.Key == Key.L)
                    KeyboardKeyL = false;
                if (state.IsPressed & state.Key == Key.Semicolon)
                    KeyboardKeySemicolon = true;
                if (state.IsReleased & state.Key == Key.Semicolon)
                    KeyboardKeySemicolon = false;
                if (state.IsPressed & state.Key == Key.Apostrophe)
                    KeyboardKeyApostrophe = true;
                if (state.IsReleased & state.Key == Key.Apostrophe)
                    KeyboardKeyApostrophe = false;
                if (state.IsPressed & state.Key == Key.Grave)
                    KeyboardKeyGrave = true;
                if (state.IsReleased & state.Key == Key.Grave)
                    KeyboardKeyGrave = false;
                if (state.IsPressed & state.Key == Key.LeftShift)
                    KeyboardKeyLeftShift = true;
                if (state.IsReleased & state.Key == Key.LeftShift)
                    KeyboardKeyLeftShift = false;
                if (state.IsPressed & state.Key == Key.Backslash)
                    KeyboardKeyBackslash = true;
                if (state.IsReleased & state.Key == Key.Backslash)
                    KeyboardKeyBackslash = false;
                if (state.IsPressed & state.Key == Key.Z)
                    KeyboardKeyZ = true;
                if (state.IsReleased & state.Key == Key.Z)
                    KeyboardKeyZ = false;
                if (state.IsPressed & state.Key == Key.X)
                    KeyboardKeyX = true;
                if (state.IsReleased & state.Key == Key.X)
                    KeyboardKeyX = false;
                if (state.IsPressed & state.Key == Key.C)
                    KeyboardKeyC = true;
                if (state.IsReleased & state.Key == Key.C)
                    KeyboardKeyC = false;
                if (state.IsPressed & state.Key == Key.V)
                    KeyboardKeyV = true;
                if (state.IsReleased & state.Key == Key.V)
                    KeyboardKeyV = false;
                if (state.IsPressed & state.Key == Key.B)
                    KeyboardKeyB = true;
                if (state.IsReleased & state.Key == Key.B)
                    KeyboardKeyB = false;
                if (state.IsPressed & state.Key == Key.N)
                    KeyboardKeyN = true;
                if (state.IsReleased & state.Key == Key.N)
                    KeyboardKeyN = false;
                if (state.IsPressed & state.Key == Key.M)
                    KeyboardKeyM = true;
                if (state.IsReleased & state.Key == Key.M)
                    KeyboardKeyM = false;
                if (state.IsPressed & state.Key == Key.Comma)
                    KeyboardKeyComma = true;
                if (state.IsReleased & state.Key == Key.Comma)
                    KeyboardKeyComma = false;
                if (state.IsPressed & state.Key == Key.Period)
                    KeyboardKeyPeriod = true;
                if (state.IsReleased & state.Key == Key.Period)
                    KeyboardKeyPeriod = false;
                if (state.IsPressed & state.Key == Key.Slash)
                    KeyboardKeySlash = true;
                if (state.IsReleased & state.Key == Key.Slash)
                    KeyboardKeySlash = false;
                if (state.IsPressed & state.Key == Key.RightShift)
                    KeyboardKeyRightShift = true;
                if (state.IsReleased & state.Key == Key.RightShift)
                    KeyboardKeyRightShift = false;
                if (state.IsPressed & state.Key == Key.Multiply)
                    KeyboardKeyMultiply = true;
                if (state.IsReleased & state.Key == Key.Multiply)
                    KeyboardKeyMultiply = false;
                if (state.IsPressed & state.Key == Key.LeftAlt)
                    KeyboardKeyLeftAlt = true;
                if (state.IsReleased & state.Key == Key.LeftAlt)
                    KeyboardKeyLeftAlt = false;
                if (state.IsPressed & state.Key == Key.Space)
                    KeyboardKeySpace = true;
                if (state.IsReleased & state.Key == Key.Space)
                    KeyboardKeySpace = false;
                if (state.IsPressed & state.Key == Key.Capital)
                    KeyboardKeyCapital = true;
                if (state.IsReleased & state.Key == Key.Capital)
                    KeyboardKeyCapital = false;
                if (state.IsPressed & state.Key == Key.F1)
                    KeyboardKeyF1 = true;
                if (state.IsReleased & state.Key == Key.F1)
                    KeyboardKeyF1 = false;
                if (state.IsPressed & state.Key == Key.F2)
                    KeyboardKeyF2 = true;
                if (state.IsReleased & state.Key == Key.F2)
                    KeyboardKeyF2 = false;
                if (state.IsPressed & state.Key == Key.F3)
                    KeyboardKeyF3 = true;
                if (state.IsReleased & state.Key == Key.F3)
                    KeyboardKeyF3 = false;
                if (state.IsPressed & state.Key == Key.F4)
                    KeyboardKeyF4 = true;
                if (state.IsReleased & state.Key == Key.F4)
                    KeyboardKeyF4 = false;
                if (state.IsPressed & state.Key == Key.F5)
                    KeyboardKeyF5 = true;
                if (state.IsReleased & state.Key == Key.F5)
                    KeyboardKeyF5 = false;
                if (state.IsPressed & state.Key == Key.F6)
                    KeyboardKeyF6 = true;
                if (state.IsReleased & state.Key == Key.F6)
                    KeyboardKeyF6 = false;
                if (state.IsPressed & state.Key == Key.F7)
                    KeyboardKeyF7 = true;
                if (state.IsReleased & state.Key == Key.F7)
                    KeyboardKeyF7 = false;
                if (state.IsPressed & state.Key == Key.F8)
                    KeyboardKeyF8 = true;
                if (state.IsReleased & state.Key == Key.F8)
                    KeyboardKeyF8 = false;
                if (state.IsPressed & state.Key == Key.F9)
                    KeyboardKeyF9 = true;
                if (state.IsReleased & state.Key == Key.F9)
                    KeyboardKeyF9 = false;
                if (state.IsPressed & state.Key == Key.F10)
                    KeyboardKeyF10 = true;
                if (state.IsReleased & state.Key == Key.F10)
                    KeyboardKeyF10 = false;
                if (state.IsPressed & state.Key == Key.NumberLock)
                    KeyboardKeyNumberLock = true;
                if (state.IsReleased & state.Key == Key.NumberLock)
                    KeyboardKeyNumberLock = false;
                if (state.IsPressed & state.Key == Key.ScrollLock)
                    KeyboardKeyScrollLock = true;
                if (state.IsReleased & state.Key == Key.ScrollLock)
                    KeyboardKeyScrollLock = false;
                if (state.IsPressed & state.Key == Key.NumberPad7)
                    KeyboardKeyNumberPad7 = true;
                if (state.IsReleased & state.Key == Key.NumberPad7)
                    KeyboardKeyNumberPad7 = false;
                if (state.IsPressed & state.Key == Key.NumberPad8)
                    KeyboardKeyNumberPad8 = true;
                if (state.IsReleased & state.Key == Key.NumberPad8)
                    KeyboardKeyNumberPad8 = false;
                if (state.IsPressed & state.Key == Key.NumberPad9)
                    KeyboardKeyNumberPad9 = true;
                if (state.IsReleased & state.Key == Key.NumberPad9)
                    KeyboardKeyNumberPad9 = false;
                if (state.IsPressed & state.Key == Key.Subtract)
                    KeyboardKeySubtract = true;
                if (state.IsReleased & state.Key == Key.Subtract)
                    KeyboardKeySubtract = false;
                if (state.IsPressed & state.Key == Key.NumberPad4)
                    KeyboardKeyNumberPad4 = true;
                if (state.IsReleased & state.Key == Key.NumberPad4)
                    KeyboardKeyNumberPad4 = false;
                if (state.IsPressed & state.Key == Key.NumberPad5)
                    KeyboardKeyNumberPad5 = true;
                if (state.IsReleased & state.Key == Key.NumberPad5)
                    KeyboardKeyNumberPad5 = false;
                if (state.IsPressed & state.Key == Key.NumberPad6)
                    KeyboardKeyNumberPad6 = true;
                if (state.IsReleased & state.Key == Key.NumberPad6)
                    KeyboardKeyNumberPad6 = false;
                if (state.IsPressed & state.Key == Key.Add)
                    KeyboardKeyAdd = true;
                if (state.IsReleased & state.Key == Key.Add)
                    KeyboardKeyAdd = false;
                if (state.IsPressed & state.Key == Key.NumberPad1)
                    KeyboardKeyNumberPad1 = true;
                if (state.IsReleased & state.Key == Key.NumberPad1)
                    KeyboardKeyNumberPad1 = false;
                if (state.IsPressed & state.Key == Key.NumberPad2)
                    KeyboardKeyNumberPad2 = true;
                if (state.IsReleased & state.Key == Key.NumberPad2)
                    KeyboardKeyNumberPad2 = false;
                if (state.IsPressed & state.Key == Key.NumberPad3)
                    KeyboardKeyNumberPad3 = true;
                if (state.IsReleased & state.Key == Key.NumberPad3)
                    KeyboardKeyNumberPad3 = false;
                if (state.IsPressed & state.Key == Key.NumberPad0)
                    KeyboardKeyNumberPad0 = true;
                if (state.IsReleased & state.Key == Key.NumberPad0)
                    KeyboardKeyNumberPad0 = false;
                if (state.IsPressed & state.Key == Key.Decimal)
                    KeyboardKeyDecimal = true;
                if (state.IsReleased & state.Key == Key.Decimal)
                    KeyboardKeyDecimal = false;
                if (state.IsPressed & state.Key == Key.Oem102)
                    KeyboardKeyOem102 = true;
                if (state.IsReleased & state.Key == Key.Oem102)
                    KeyboardKeyOem102 = false;
                if (state.IsPressed & state.Key == Key.F11)
                    KeyboardKeyF11 = true;
                if (state.IsReleased & state.Key == Key.F11)
                    KeyboardKeyF11 = false;
                if (state.IsPressed & state.Key == Key.F12)
                    KeyboardKeyF12 = true;
                if (state.IsReleased & state.Key == Key.F12)
                    KeyboardKeyF12 = false;
                if (state.IsPressed & state.Key == Key.F13)
                    KeyboardKeyF13 = true;
                if (state.IsReleased & state.Key == Key.F13)
                    KeyboardKeyF13 = false;
                if (state.IsPressed & state.Key == Key.F14)
                    KeyboardKeyF14 = true;
                if (state.IsReleased & state.Key == Key.F14)
                    KeyboardKeyF14 = false;
                if (state.IsPressed & state.Key == Key.F15)
                    KeyboardKeyF15 = true;
                if (state.IsReleased & state.Key == Key.F15)
                    KeyboardKeyF15 = false;
                if (state.IsPressed & state.Key == Key.Kana)
                    KeyboardKeyKana = true;
                if (state.IsReleased & state.Key == Key.Kana)
                    KeyboardKeyKana = false;
                if (state.IsPressed & state.Key == Key.AbntC1)
                    KeyboardKeyAbntC1 = true;
                if (state.IsReleased & state.Key == Key.AbntC1)
                    KeyboardKeyAbntC1 = false;
                if (state.IsPressed & state.Key == Key.Convert)
                    KeyboardKeyConvert = true;
                if (state.IsReleased & state.Key == Key.Convert)
                    KeyboardKeyConvert = false;
                if (state.IsPressed & state.Key == Key.NoConvert)
                    KeyboardKeyNoConvert = true;
                if (state.IsReleased & state.Key == Key.NoConvert)
                    KeyboardKeyNoConvert = false;
                if (state.IsPressed & state.Key == Key.Yen)
                    KeyboardKeyYen = true;
                if (state.IsReleased & state.Key == Key.Yen)
                    KeyboardKeyYen = false;
                if (state.IsPressed & state.Key == Key.AbntC2)
                    KeyboardKeyAbntC2 = true;
                if (state.IsReleased & state.Key == Key.AbntC2)
                    KeyboardKeyAbntC2 = false;
                if (state.IsPressed & state.Key == Key.NumberPadEquals)
                    KeyboardKeyNumberPadEquals = true;
                if (state.IsReleased & state.Key == Key.NumberPadEquals)
                    KeyboardKeyNumberPadEquals = false;
                if (state.IsPressed & state.Key == Key.PreviousTrack)
                    KeyboardKeyPreviousTrack = true;
                if (state.IsReleased & state.Key == Key.PreviousTrack)
                    KeyboardKeyPreviousTrack = false;
                if (state.IsPressed & state.Key == Key.AT)
                    KeyboardKeyAT = true;
                if (state.IsReleased & state.Key == Key.AT)
                    KeyboardKeyAT = false;
                if (state.IsPressed & state.Key == Key.Colon)
                    KeyboardKeyColon = true;
                if (state.IsReleased & state.Key == Key.Colon)
                    KeyboardKeyColon = false;
                if (state.IsPressed & state.Key == Key.Underline)
                    KeyboardKeyUnderline = true;
                if (state.IsReleased & state.Key == Key.Underline)
                    KeyboardKeyUnderline = false;
                if (state.IsPressed & state.Key == Key.Kanji)
                    KeyboardKeyKanji = true;
                if (state.IsReleased & state.Key == Key.Kanji)
                    KeyboardKeyKanji = false;
                if (state.IsPressed & state.Key == Key.Stop)
                    KeyboardKeyStop = true;
                if (state.IsReleased & state.Key == Key.Stop)
                    KeyboardKeyStop = false;
                if (state.IsPressed & state.Key == Key.AX)
                    KeyboardKeyAX = true;
                if (state.IsReleased & state.Key == Key.AX)
                    KeyboardKeyAX = false;
                if (state.IsPressed & state.Key == Key.Unlabeled)
                    KeyboardKeyUnlabeled = true;
                if (state.IsReleased & state.Key == Key.Unlabeled)
                    KeyboardKeyUnlabeled = false;
                if (state.IsPressed & state.Key == Key.NextTrack)
                    KeyboardKeyNextTrack = true;
                if (state.IsReleased & state.Key == Key.NextTrack)
                    KeyboardKeyNextTrack = false;
                if (state.IsPressed & state.Key == Key.NumberPadEnter)
                    KeyboardKeyNumberPadEnter = true;
                if (state.IsReleased & state.Key == Key.NumberPadEnter)
                    KeyboardKeyNumberPadEnter = false;
                if (state.IsPressed & state.Key == Key.RightControl)
                    KeyboardKeyRightControl = true;
                if (state.IsReleased & state.Key == Key.RightControl)
                    KeyboardKeyRightControl = false;
                if (state.IsPressed & state.Key == Key.Mute)
                    KeyboardKeyMute = true;
                if (state.IsReleased & state.Key == Key.Mute)
                    KeyboardKeyMute = false;
                if (state.IsPressed & state.Key == Key.Calculator)
                    KeyboardKeyCalculator = true;
                if (state.IsReleased & state.Key == Key.Calculator)
                    KeyboardKeyCalculator = false;
                if (state.IsPressed & state.Key == Key.PlayPause)
                    KeyboardKeyPlayPause = true;
                if (state.IsReleased & state.Key == Key.PlayPause)
                    KeyboardKeyPlayPause = false;
                if (state.IsPressed & state.Key == Key.MediaStop)
                    KeyboardKeyMediaStop = true;
                if (state.IsReleased & state.Key == Key.MediaStop)
                    KeyboardKeyMediaStop = false;
                if (state.IsPressed & state.Key == Key.VolumeDown)
                    KeyboardKeyVolumeDown = true;
                if (state.IsReleased & state.Key == Key.VolumeDown)
                    KeyboardKeyVolumeDown = false;
                if (state.IsPressed & state.Key == Key.VolumeUp)
                    KeyboardKeyVolumeUp = true;
                if (state.IsReleased & state.Key == Key.VolumeUp)
                    KeyboardKeyVolumeUp = false;
                if (state.IsPressed & state.Key == Key.WebHome)
                    KeyboardKeyWebHome = true;
                if (state.IsReleased & state.Key == Key.WebHome)
                    KeyboardKeyWebHome = false;
                if (state.IsPressed & state.Key == Key.NumberPadComma)
                    KeyboardKeyNumberPadComma = true;
                if (state.IsReleased & state.Key == Key.NumberPadComma)
                    KeyboardKeyNumberPadComma = false;
                if (state.IsPressed & state.Key == Key.Divide)
                    KeyboardKeyDivide = true;
                if (state.IsReleased & state.Key == Key.Divide)
                    KeyboardKeyDivide = false;
                if (state.IsPressed & state.Key == Key.PrintScreen)
                    KeyboardKeyPrintScreen = true;
                if (state.IsReleased & state.Key == Key.PrintScreen)
                    KeyboardKeyPrintScreen = false;
                if (state.IsPressed & state.Key == Key.RightAlt)
                    KeyboardKeyRightAlt = true;
                if (state.IsReleased & state.Key == Key.RightAlt)
                    KeyboardKeyRightAlt = false;
                if (state.IsPressed & state.Key == Key.Pause)
                    KeyboardKeyPause = true;
                if (state.IsReleased & state.Key == Key.Pause)
                    KeyboardKeyPause = false;
                if (state.IsPressed & state.Key == Key.Home)
                    KeyboardKeyHome = true;
                if (state.IsReleased & state.Key == Key.Home)
                    KeyboardKeyHome = false;
                if (state.IsPressed & state.Key == Key.Up)
                    KeyboardKeyUp = true;
                if (state.IsReleased & state.Key == Key.Up)
                    KeyboardKeyUp = false;
                if (state.IsPressed & state.Key == Key.PageUp)
                    KeyboardKeyPageUp = true;
                if (state.IsReleased & state.Key == Key.PageUp)
                    KeyboardKeyPageUp = false;
                if (state.IsPressed & state.Key == Key.Left)
                    KeyboardKeyLeft = true;
                if (state.IsReleased & state.Key == Key.Left)
                    KeyboardKeyLeft = false;
                if (state.IsPressed & state.Key == Key.Right)
                    KeyboardKeyRight = true;
                if (state.IsReleased & state.Key == Key.Right)
                    KeyboardKeyRight = false;
                if (state.IsPressed & state.Key == Key.End)
                    KeyboardKeyEnd = true;
                if (state.IsReleased & state.Key == Key.End)
                    KeyboardKeyEnd = false;
                if (state.IsPressed & state.Key == Key.Down)
                    KeyboardKeyDown = true;
                if (state.IsReleased & state.Key == Key.Down)
                    KeyboardKeyDown = false;
                if (state.IsPressed & state.Key == Key.PageDown)
                    KeyboardKeyPageDown = true;
                if (state.IsReleased & state.Key == Key.PageDown)
                    KeyboardKeyPageDown = false;
                if (state.IsPressed & state.Key == Key.Insert)
                    KeyboardKeyInsert = true;
                if (state.IsReleased & state.Key == Key.Insert)
                    KeyboardKeyInsert = false;
                if (state.IsPressed & state.Key == Key.Delete)
                    KeyboardKeyDelete = true;
                if (state.IsReleased & state.Key == Key.Delete)
                    KeyboardKeyDelete = false;
                if (state.IsPressed & state.Key == Key.LeftWindowsKey)
                    KeyboardKeyLeftWindowsKey = true;
                if (state.IsReleased & state.Key == Key.LeftWindowsKey)
                    KeyboardKeyLeftWindowsKey = false;
                if (state.IsPressed & state.Key == Key.RightWindowsKey)
                    KeyboardKeyRightWindowsKey = true;
                if (state.IsReleased & state.Key == Key.RightWindowsKey)
                    KeyboardKeyRightWindowsKey = false;
                if (state.IsPressed & state.Key == Key.Applications)
                    KeyboardKeyApplications = true;
                if (state.IsReleased & state.Key == Key.Applications)
                    KeyboardKeyApplications = false;
                if (state.IsPressed & state.Key == Key.Power)
                    KeyboardKeyPower = true;
                if (state.IsReleased & state.Key == Key.Power)
                    KeyboardKeyPower = false;
                if (state.IsPressed & state.Key == Key.Sleep)
                    KeyboardKeySleep = true;
                if (state.IsReleased & state.Key == Key.Sleep)
                    KeyboardKeySleep = false;
                if (state.IsPressed & state.Key == Key.Wake)
                    KeyboardKeyWake = true;
                if (state.IsReleased & state.Key == Key.Wake)
                    KeyboardKeyWake = false;
                if (state.IsPressed & state.Key == Key.WebSearch)
                    KeyboardKeyWebSearch = true;
                if (state.IsReleased & state.Key == Key.WebSearch)
                    KeyboardKeyWebSearch = false;
                if (state.IsPressed & state.Key == Key.WebFavorites)
                    KeyboardKeyWebFavorites = true;
                if (state.IsReleased & state.Key == Key.WebFavorites)
                    KeyboardKeyWebFavorites = false;
                if (state.IsPressed & state.Key == Key.WebRefresh)
                    KeyboardKeyWebRefresh = true;
                if (state.IsReleased & state.Key == Key.WebRefresh)
                    KeyboardKeyWebRefresh = false;
                if (state.IsPressed & state.Key == Key.WebStop)
                    KeyboardKeyWebStop = true;
                if (state.IsReleased & state.Key == Key.WebStop)
                    KeyboardKeyWebStop = false;
                if (state.IsPressed & state.Key == Key.WebForward)
                    KeyboardKeyWebForward = true;
                if (state.IsReleased & state.Key == Key.WebForward)
                    KeyboardKeyWebForward = false;
                if (state.IsPressed & state.Key == Key.WebBack)
                    KeyboardKeyWebBack = true;
                if (state.IsReleased & state.Key == Key.WebBack)
                    KeyboardKeyWebBack = false;
                if (state.IsPressed & state.Key == Key.MyComputer)
                    KeyboardKeyMyComputer = true;
                if (state.IsReleased & state.Key == Key.MyComputer)
                    KeyboardKeyMyComputer = false;
                if (state.IsPressed & state.Key == Key.Mail)
                    KeyboardKeyMail = true;
                if (state.IsReleased & state.Key == Key.Mail)
                    KeyboardKeyMail = false;
                if (state.IsPressed & state.Key == Key.MediaSelect)
                    KeyboardKeyMediaSelect = true;
                if (state.IsReleased & state.Key == Key.MediaSelect)
                    KeyboardKeyMediaSelect = false;
                if (state.IsPressed & state.Key == Key.Unknown)
                    KeyboardKeyUnknown = true;
                if (state.IsReleased & state.Key == Key.Unknown)
                    KeyboardKeyUnknown = false;
            }
        }
    }
}