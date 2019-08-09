using System.Threading;
using Android.OS;
using Android.Views;
using Android.Widget;
using testeCTS.Droid.Helpers;

namespace testeCTS.Droid
{
    public class SctsFragment : Android.Support.V4.App.Fragment, IFragmentVisible
    {
        Teste SCTs = Teste.GetInstence();
        public static SctsFragment NewInstance() =>
            new SctsFragment { Arguments = new Bundle() };

        public AboutViewModel ViewModel { get; set; }

        public override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            // Create your fragment here
        }

        Button CheckButton;
        EditText urlTest;
        TextView TestStatus;

        public override View OnCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
        {
            var view = inflater.Inflate(Resource.Layout.fragment_about, container, false);
            ViewModel = new AboutViewModel();
            CheckButton = view.FindViewById<Button>(Resource.Id.button_learn_more);
            urlTest = view.FindViewById<EditText>(Resource.Id.editText1);
            TestStatus = view.FindViewById<TextView>(Resource.Id.textView1);
            return view;
        }

        public override void OnStart()
        {
            base.OnStart();
            CheckButton.Click += CheckButton_Click;
        }

        public override void OnStop()
        {
            base.OnStop();
            CheckButton.Click -= CheckButton_Click;
        }

        public void BecameVisible()
        {

        }

        void CheckButton_Click(object sender, System.EventArgs e)
        {
            Thread thread = new Thread(() =>
            {
                TestStatus.Text = "Processando...";
                if (SCTs.CheckSCTS(urlTest.Text))
                {
                    TestStatus.Text = "Certificado válido";
                }
                else
                {
                    TestStatus.Text = "Certificado inválido";
                }

            });
            thread.Start();
        }
    }
}
