using System;
using System.Threading;
using Android.OS;
using Android.Views;
using Android.Widget;

namespace testeCTS.Droid
{
    public class AboutFragment : Android.Support.V4.App.Fragment, IFragmentVisible
    {
        teste SCTs = new teste();
        public static AboutFragment NewInstance() =>
            new AboutFragment { Arguments = new Bundle() };

        public AboutViewModel ViewModel { get; set; }

        public override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            // Create your fragment here
        }

        Button learnMoreButton;
        EditText urlTest;
        TextView TestStatus;

        public override View OnCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
        {
            var view = inflater.Inflate(Resource.Layout.fragment_about, container, false);
            ViewModel = new AboutViewModel();
            learnMoreButton = view.FindViewById<Button>(Resource.Id.button_learn_more);
            urlTest = view.FindViewById<EditText>(Resource.Id.editText1);
            TestStatus = view.FindViewById<TextView>(Resource.Id.textView1);
            return view;
        }

        public override void OnStart()
        {
            base.OnStart();
            learnMoreButton.Click += LearnMoreButton_Click;
        }

        public override void OnStop()
        {
            base.OnStop();
            learnMoreButton.Click -= LearnMoreButton_Click;
        }

        public void BecameVisible()
        {

        }

        void LearnMoreButton_Click(object sender, System.EventArgs e)
        {
            //ViewModel.OpenWebCommand.Execute(null);


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
