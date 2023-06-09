/*
 * Copyright (c) 2021-present Sigma-Soft, Ltd.
 * Aleksei Ponomarev
 *
 * Copyright (c) 2023-present unTill Pro, Ltd.
 * @author Maxim Geraskin
 * Deep refactoring, no timers
 *
 *
 */

package in10nmem

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/untillpro/goutils/logger"
	"github.com/voedger/voedger/pkg/appdef"
	"github.com/voedger/voedger/pkg/in10n"
	istructs "github.com/voedger/voedger/pkg/istructs"
)

type callbackMock struct {
	data chan UpdateUnit
}

func Test_BasicUsage(t *testing.T) {

	logger.SetLogLevel(logger.LogLevelTrace)

	var wg sync.WaitGroup
	c := new(callbackMock)
	c.data = make(chan UpdateUnit)

	projectionKeyExample := in10n.ProjectionKey{
		App:        istructs.AppQName_test1_app1,
		Projection: appdef.NewQName("test", "restaurant"),
		WS:         istructs.WSID(0),
	}

	quotasExample := in10n.Quotas{
		Channels:               1,
		ChannelsPerSubject:     1,
		Subsciptions:           1,
		SubsciptionsPerSubject: 1,
	}
	req := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())

	broker, cleanup := ProvideEx2(quotasExample, time.Now)
	defer cleanup()

	var channel in10n.ChannelID
	t.Run("Create channel.", func(t *testing.T) {
		var subject istructs.SubjectLogin = "paa"
		var err error
		channel, err = broker.NewChannel(subject, 24*time.Hour)
		req.NoError(err)
		req.NotNil(channel)
	})

	t.Run("Check channel count. count must be 1.", func(t *testing.T) {
		numChannels := broker.MetricNumChannels()
		req.Equal(1, numChannels)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.WatchChannel(ctx, channel, c.updatesMock)
	}()

	t.Run("Subscribe on projection.", func(t *testing.T) {
		var notExistsChannel = "NotExistChannel"
		// Try to subscribe on projection in not exist channel
		// must receive error ErrChannelNotExists
		err := broker.Subscribe(in10n.ChannelID(notExistsChannel), projectionKeyExample)
		req.ErrorIs(err, in10n.ErrChannelDoesNotExist)

		// check subscriptions, numSubscriptions must be equal 0
		numSubscriptions := broker.MetricNumSubcriptions()
		req.Equal(0, numSubscriptions)

		// Subscribe on exist channel numSubscriptions must be equal 1
		require.NoError(t, broker.Subscribe(channel, projectionKeyExample))
		numSubscriptions = broker.MetricNumSubcriptions()
		req.Equal(1, numSubscriptions)

		// Unsubscribe from not exist channel, raise error in10n.ErrChannelDoesNotExist
		err = broker.Unsubscribe("Not exists channel", projectionKeyExample)
		req.ErrorIs(err, in10n.ErrChannelDoesNotExist)

		// Unsubscribe from an existing channel
		err = broker.Unsubscribe(channel, projectionKeyExample)
		req.NoError(err)
		// After unsubscribe numSubscriptions must be equal 0
		numSubscriptions = broker.MetricNumSubcriptions()
		req.Equal(0, numSubscriptions)

		// Subscribe for and existing channel numSubscriptions must be equal 1
		require.NoError(t, broker.Subscribe(channel, projectionKeyExample))
		numSubscriptions = broker.MetricNumSubcriptions()
		req.Equal(1, numSubscriptions)

	})

	broker.Update(projectionKeyExample, istructs.Offset(122))
	broker.Update(projectionKeyExample, istructs.Offset(123))
	broker.Update(projectionKeyExample, istructs.Offset(124))
	broker.Update(projectionKeyExample, istructs.Offset(125))
	broker.Update(projectionKeyExample, istructs.Offset(126))

	for update := range c.data {
		logger.Info("update.Offset: ", update.Offset)
		if update.Offset == istructs.Offset(126) {
			break
		}
	}
	cancel()
	logger.Info("wg.Wait()")
	wg.Wait()
}

func (c *callbackMock) updatesMock(projection in10n.ProjectionKey, offset istructs.Offset) {
	var unit = UpdateUnit{
		Projection: projection,
		Offset:     offset,
	}
	c.data <- unit
}

func Test_SubscribeUnsubscribe(t *testing.T) {

	var wg sync.WaitGroup

	cb1 := new(callbackMock)
	cb1.data = make(chan UpdateUnit, 1)

	cb2 := new(callbackMock)
	cb2.data = make(chan UpdateUnit, 1)

	ctx, cancel := context.WithCancel(context.Background())

	projectionKey1 := in10n.ProjectionKey{
		App:        istructs.AppQName_test1_app1,
		Projection: appdef.NewQName("test", "restaurant"),
		WS:         istructs.WSID(0),
	}
	projectionKey2 := in10n.ProjectionKey{
		App:        istructs.AppQName_test1_app1,
		Projection: appdef.NewQName("test", "restaurant2"),
		WS:         istructs.WSID(0),
	}

	quotasExample := in10n.Quotas{
		Channels:               10,
		ChannelsPerSubject:     10,
		Subsciptions:           10,
		SubsciptionsPerSubject: 10,
	}
	req := require.New(t)

	nb, cleanup := ProvideEx2(quotasExample, time.Now)
	defer cleanup()

	var channel1ID in10n.ChannelID
	t.Run("Create and subscribe channel 1", func(t *testing.T) {
		var subject istructs.SubjectLogin = "paa"
		var err error
		channel1ID, err = nb.NewChannel(subject, 24*time.Hour)
		req.NoError(err)

		err = nb.Subscribe(channel1ID, projectionKey1)
		req.NoError(err)

		err = nb.Subscribe(channel1ID, projectionKey2)
		req.NoError(err)

		wg.Add(1)
		go func() {
			nb.WatchChannel(ctx, channel1ID, cb1.updatesMock)
			wg.Done()
		}()
	})

	var channel2ID in10n.ChannelID
	t.Run("Create and subscribe channel 2", func(t *testing.T) {
		var subject istructs.SubjectLogin = "paa"
		var err error
		channel2ID, err = nb.NewChannel(subject, 24*time.Hour)
		req.NoError(err)

		err = nb.Subscribe(channel2ID, projectionKey1)
		req.NoError(err)

		err = nb.Subscribe(channel2ID, projectionKey2)
		req.NoError(err)

		wg.Add(1)
		go func() {
			nb.WatchChannel(ctx, channel2ID, cb2.updatesMock)
			wg.Done()
		}()
	})

	// Update and see data

	for i := 1; i < 10; i++ {
		nb.Update(projectionKey1, istructs.Offset(i))
		<-cb1.data
		<-cb2.data
		nb.Update(projectionKey2, istructs.Offset(i))
		<-cb1.data
		<-cb2.data
	}

	// Unsubscribe all channels from projectionKey1

	nb.Unsubscribe(channel1ID, projectionKey1)
	nb.Unsubscribe(channel2ID, projectionKey1)

	for i := 100; i < 110; i++ {

		nb.Update(projectionKey2, istructs.Offset(i))
		<-cb1.data
		<-cb2.data

		nb.Update(projectionKey1, istructs.Offset(i))
		select {
		case <-cb1.data:
			t.Error("cb1.data must be empty")
		default:
			// TODO note that cb1.data may come later, should wait for broker idleness somehow
		}
		select {
		case <-cb2.data:
			t.Error("cb2.data must be empty")
			// TODO See note above
		default:
		}
	}
	cancel()
	wg.Wait()

}

// Try watch on not exists channel. WatchChannel must exit.
func TestWatchNotExistsChannel(t *testing.T) {
	req := require.New(t)

	quotasExample := in10n.Quotas{
		Channels:               1,
		ChannelsPerSubject:     1,
		Subsciptions:           1,
		SubsciptionsPerSubject: 1,
	}

	broker, cleanup := ProvideEx2(quotasExample, time.Now)
	defer cleanup()
	ctx := context.TODO()

	t.Run("Create channel.", func(t *testing.T) {
		var subject istructs.SubjectLogin = "paa"
		channel, err := broker.NewChannel(subject, 24*time.Hour)
		req.NoError(err)
		req.NotNil(channel)
	})

	t.Run("Try watch not exist channel", func(t *testing.T) {
		req.Panics(func() {
			broker.WatchChannel(ctx, "not exist channel id", nil)
		}, "When try watch not exists channel - must panics")

	})
}

func TestQuotas(t *testing.T) {

	t.Parallel()

	req := require.New(t)
	quotasExample := in10n.Quotas{
		Channels:               100,
		ChannelsPerSubject:     10,
		Subsciptions:           1000,
		SubsciptionsPerSubject: 100,
	}

	t.Run("Test channel quotas per subject. We create more channels than allowed for subject.", func(t *testing.T) {
		broker, cleanup := ProvideEx2(quotasExample, time.Now)
		defer cleanup()
		for i := 0; i <= 10; i++ {
			_, err := broker.NewChannel("paa", 24*time.Hour)
			if i == 10 {
				req.ErrorIs(err, in10n.ErrQuotaExceeded_ChannelsPerSubject)
			}
		}
	})

	t.Run("Test channel quotas for the whole service. We create more channels than allowed for service.", func(t *testing.T) {
		broker, cleanup := ProvideEx2(quotasExample, time.Now)
		defer cleanup()
		var subject istructs.SubjectLogin
		for i := 0; i < 10; i++ {
			subject = istructs.SubjectLogin("paa" + strconv.Itoa(i))
			for c := 0; c <= 10; c++ {
				_, err := broker.NewChannel(subject, 24*time.Hour)
				if i == 9 && c == 10 {
					req.ErrorIs(err, in10n.ErrQuotaExceeded_Channels)
				}
			}
		}
	})

	t.Run("Test subscription quotas for the whole service. We create more subscription than allowed for service.", func(t *testing.T) {
		projectionKeyExample := in10n.ProjectionKey{
			App:        istructs.AppQName_test1_app1,
			Projection: appdef.NewQName("test", "restaurant"),
			WS:         istructs.WSID(1),
		}
		broker, cleanup := ProvideEx2(quotasExample, time.Now)
		defer cleanup()
		var subject istructs.SubjectLogin
		for i := 0; i < 100; i++ {
			subject = istructs.SubjectLogin("paa" + strconv.Itoa(i))
			channel, err := broker.NewChannel(subject, 24*time.Hour)
			req.NoError(err)
			for g := 0; g < 10; g++ {
				projectionKeyExample.WS = istructs.WSID(i + g)
				err = broker.Subscribe(channel, projectionKeyExample)
				req.NoError(err)
				if i == 99 && g == 9 {
					numSubscriptions := broker.MetricNumSubcriptions()
					req.Equal(1000, numSubscriptions)
					projectionKeyExample.WS = istructs.WSID(i + 100000)
					err = broker.Subscribe(channel, projectionKeyExample)
					req.ErrorIs(err, in10n.ErrQuotaExceeded_Subsciptions)
				}
			}
		}

	})

}
