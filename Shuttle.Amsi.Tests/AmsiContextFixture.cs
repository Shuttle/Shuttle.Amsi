using NUnit.Framework;

namespace Shuttle.Amsi.Tests
{
    [TestFixture]
    public class AmsiContextFixture
    {
        [Test]
        public void Should_be_able_to_determine_AMSI_availability()
        {
            using (var context = new AmsiContext())
            {
                Assert.That(context.IsAvailable, Is.True);
            }
        }
    }
}
